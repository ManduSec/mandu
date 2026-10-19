/**
 * arbiter-source-reveal.test — the arbiter-backed reveals over a MOCK arbiter socket:
 *   the §4.2c deep `desymbolize`, the §4.2f paired rows, the shallow
 *   `resolveSymbol`, and the product page's /api/home/agent (§4.25b).
 *
 * Mandu-new test (NO reference origin). The mock arbiter and canned events
 * live in arbiter-source-fixtures.ts (split out of the former
 * arbiter-source.test.ts).
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";

import { DashboardServer } from "../../src/server.js";
import { ArbiterEventSource } from "../../src/event-source.js";
import {
  OUTER_SYM, RAW_NOTES, SHELL_SECRET, PAGE_OUTER, PAGE_INNER, PAGE_SECRET, PAGE_TABLE,
  startSharedFixtures, type MockArbiter,
} from "./arbiter-source-fixtures.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../unit/admin-session.js";

// ── Shared fixtures ───────────────────────────────────────────────────────────

let arbiter: MockArbiter;
let source: ArbiterEventSource;

before(async () => {
  ({ arbiter, source } = await startSharedFixtures());
});

after(async () => {
  source.close();
  await arbiter.close();
});

// ── 1b. desymbolize: the §4.2c delivery-zone deep reveal, over the wire ────────

test("ArbiterEventSource.desymbolize deep-resolves a nested chain via the arbiter op", async () => {
  const resolved = await source.desymbolize(`reply: ${OUTER_SYM}`);
  assert.equal(resolved, `reply: 1\t${RAW_NOTES}\n2\t`, "the nested chain collapses to the original");
  const literal = await source.desymbolize("no symbols here");
  assert.equal(literal, "no symbols here", "symbol-free text rides through unchanged");
});

test("/api/events reveals the DELIVERED reply's symbols deeply (band value = original)", async () => {
  const e2eSource = new ArbiterEventSource({ socketPath: arbiter.socketPath });
  const server = new DashboardServer({ ...ADMIN_OPTS, source: e2eSource, log: () => {} });
  const port = await server.listen(0);
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/events?session=sess-nested`, { headers: CSRF_ADMIN });
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      viewModel: { dualLanes: { steps: Array<{ step: string; final?: boolean; symbols?: Array<{ name: string; value: string | null }> }> } };
    };
    const final = body.viewModel.dualLanes.steps.find((s) => s.step === "response" && s.final);
    assert.ok(final, "the delivered reply renders as the final response step");
    const band = final!.symbols!.find((s) => s.name === OUTER_SYM)!;
    assert.equal(band.value, `1\t${RAW_NOTES}\n2\t`, "the band ships the FULL original, not the twin content");
    assert.doesNotMatch(band.value!, /\$MDU:/, "no symbol token reaches the delivery band");
  } finally {
    await server.close();
  }
});

test("/api/events paired rows (§4.2f): a masked twin Read's right half is the DEEP original via the arbiter; the AI side keeps the token", async () => {
  const e2eSource = new ArbiterEventSource({ socketPath: arbiter.socketPath });
  const server = new DashboardServer({ ...ADMIN_OPTS, source: e2eSource, log: () => {} });
  const port = await server.listen(0);
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/events?session=sess-nested`, { headers: CSRF_ADMIN });
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      viewModel: {
        dualLanes: { steps: Array<{ id: string; step: string; resultAgent?: string | null }> };
        paired: { integrity: string; maskedCount: number; turns: Array<{ inputId: string | null; rows: Array<Record<string, unknown>> }> };
      };
    };
    const paired = body.viewModel.paired;
    assert.equal(paired.integrity, "on", "an UNTRUSTED classification means the integrity axis ran");
    assert.equal(paired.maskedCount, 1);
    const turn = paired.turns.find((t) => t.inputId !== null)!;
    assert.ok(turn, "the prompt opens a turn");
    const tool = turn.rows.find((r) => r.row === "tool")!;
    assert.equal(tool.masked, true);
    // The inner fs-sync symbol lives ONLY in the arbiter table: the local
    // collapse cannot reach it, the server's arbiter reveal must.
    assert.equal(tool.original, `1\t${RAW_NOTES}\n2\t`, "the right half ships the FULL original, not the twin content");
    const reply = turn.rows.find((r) => r.row === "reply")!;
    assert.match(String(reply.original), /TODO: ship the proxy\./, "the reply's 'You saw' half is deep-resolved too");
    assert.doesNotMatch(String(reply.original), /\$MDU:/);
    // Display-only: the AgentView side of the same step is untouched.
    const step = body.viewModel.dualLanes.steps.find((s) => s.id === tool.stepId)!;
    assert.equal(step.resultAgent, OUTER_SYM, "what the AI saw is still only the token");
  } finally {
    await server.close();
  }
});

test("/api/home/agent: a shell escape reads as the command, its secret output a chip; no token, no value request", async () => {
  const e2eSource = new ArbiterEventSource({ socketPath: arbiter.socketPath });
  const server = new DashboardServer({ ...ADMIN_OPTS, source: e2eSource, log: () => {} });
  const port = await server.listen(0);
  const before = arbiter.opLog.length;
  try {
    const raw = await (await fetch(`http://127.0.0.1:${port}/api/home/agent?session=sess-shell`, { headers: CSRF_ADMIN })).text();
    const page = JSON.parse(raw) as { title: string | null; story: Array<{ prompt: string | null; promptParts: unknown; shell: { command: string; output: Array<{ kind: string; text: string }> } | null }> };
    const turn = page.story.find((t) => t.shell)!;
    assert.ok(turn, "the shell escape opens a card");
    assert.deepEqual(turn.shell, { command: "cat ~/.ssh/github", output: [{ kind: "masked", text: "secret" }] });
    assert.equal(turn.prompt, "!cat ~/.ssh/github");
    assert.equal(page.title, "!cat ~/.ssh/github", "the title is the command, not the harness tags");
    assert.doesNotMatch(raw, /\$MDU:|bash-stdout/);
    assert.ok(!arbiter.opLog.slice(before).some((o) => o.includes(SHELL_SECRET)), "the secret is never even requested");
  } finally {
    await server.close();
  }
});

test("ArbiterEventSource.resolveSymbol is ONE level: nested tokens come back as tokens; unknown → null", async () => {
  assert.equal(await source.resolveSymbol(PAGE_OUTER), PAGE_TABLE[PAGE_OUTER]);
  assert.equal(await source.resolveSymbol("$MDU:Read[ffff]"), null);
});

test("/api/home/agent (§4.25b): turns from the paired rows, the block inline, originals one level at a time, never the secret", async () => {
  const e2eSource = new ArbiterEventSource({ socketPath: arbiter.socketPath });
  const server = new DashboardServer({ ...ADMIN_OPTS, source: e2eSource, log: () => {} });
  const port = await server.listen(0);
  const before = arbiter.opLog.length;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/home/agent?session=sess-page`, { headers: CSRF_ADMIN });
    assert.equal(res.status, 200);
    const raw = await res.text();
    const page = JSON.parse(raw) as { blocked: number; story: Array<{ prompt: string | null; summary: string | null; steps: Array<Record<string, any>> }> };
    const turn = page.story.find((t) => t.prompt === "Read notes.md and summarize.")!;
    assert.ok(turn, "the question opens a card");
    const read = turn.steps.find((s) => s.kind === "action" && s.outcome === "masked")!;
    assert.ok(read, "the masked Read is a step");
    assert.equal(read.split.hidden.text, "1\t# Notes: ship it\n2\t[secret]", "the twin is filled in; the secret stays a chip");
    assert.ok(turn.steps.some((s) => s.kind === "action" && s.outcome === "blocked"), "the network block is inline");
    assert.equal(page.blocked, 1);
    assert.match(String(turn.summary), /Mandu blocked 1 action and masked 1 item/);
    assert.doesNotMatch(raw, /sk-live-e2e/, "the secret value never reaches the page");
    assert.doesNotMatch(raw, /\$MDU:/);
    const asked = arbiter.opLog.slice(before).filter((o) => o.startsWith("resolve="));
    assert.ok(asked.includes(`resolve=${PAGE_OUTER}`) && asked.includes(`resolve=${PAGE_INNER}`), asked.join(","));
    assert.ok(!asked.includes(`resolve=${PAGE_SECRET}`), "the secret is never even requested");
    assert.ok(!arbiter.opLog.slice(before).includes("desymbolize"), "the product page never uses the deep reveal");
  } finally {
    await server.close();
  }
});

test("/api/events paired rows (§4.2f): the launcher's recorded protection mode reaches the view-model over the arbiter wire", async () => {
  const e2eSource = new ArbiterEventSource({ socketPath: arbiter.socketPath });
  const server = new DashboardServer({ ...ADMIN_OPTS, source: e2eSource, log: () => {} });
  const port = await server.listen(0);
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/events?session=sess-mode`, { headers: CSRF_ADMIN });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { viewModel: { paired: { integrity: string; mode: string | null } } };
    assert.equal(body.viewModel.paired.mode, "secrets");
    assert.equal(body.viewModel.paired.integrity, "off", "the record wins over the classified result's inference");
    const nested = (await (await fetch(`http://127.0.0.1:${port}/api/events?session=sess-nested`, { headers: CSRF_ADMIN })).json()) as typeof body;
    assert.equal(nested.viewModel.paired.mode, null, "a session with no record says so; integrity is inferred");
    assert.equal(nested.viewModel.paired.integrity, "on");
  } finally {
    await server.close();
  }
});

test("/api/home/agent: a CLAIMED event makes no token known, so the page never asks for its value (arbiter-human-plane.md §10.2)", async () => {
  const e2eSource = new ArbiterEventSource({ socketPath: arbiter.socketPath });
  const server = new DashboardServer({ ...ADMIN_OPTS, source: e2eSource, log: () => {} });
  const port = await server.listen(0);
  const before = arbiter.opLog.length;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/home/agent?session=sess-claim`, { headers: CSRF_ADMIN });
    assert.equal(res.status, 200);
    const asked = arbiter.opLog.slice(before).filter((o) => o.startsWith("resolve="));
    assert.ok(asked.includes(`resolve=${PAGE_OUTER}`), asked.join(","));
    // MASTER: asked (the claimed seed made the twin known)
    assert.ok(!asked.includes(`resolve=${PAGE_INNER}`), `a claim makes nothing revealable: ${asked.join(",")}`);
    assert.doesNotMatch(await res.text(), /# Notes: ship it/);
  } finally {
    await server.close();
  }
});

// ── Signed out (dashboard.md §6, read-gate.ts): what the AI saw, no value ────

test("signed out, /api/events, /api/stream and /api/home/agent carry no original and ask the arbiter for none", async () => {
  const e2eSource = new ArbiterEventSource({ socketPath: arbiter.socketPath });
  const server = new DashboardServer({ ...ADMIN_OPTS, source: e2eSource, log: () => {} });
  const port = await server.listen(0);
  const before = arbiter.opLog.length;
  try {
    // The CSRF header and Sec-Fetch-Site are what any same-host process can send.
    for (const headers of [{}, { "X-Mandu-Control": "1" }, { "Sec-Fetch-Site": "same-origin" }] as Array<Record<string, string>>) {
      const res = await fetch(`http://127.0.0.1:${port}/api/events?session=sess-nested`, { headers });
      assert.equal(res.status, 200);
      const raw = await res.text();
      const body = JSON.parse(raw) as { valuesShown: boolean; events: Array<{ input: { original: unknown } | null; output: { original: unknown; symbols: Array<{ value: unknown }> } | null }> };
      assert.equal(body.valuesShown, false);
      assert.ok(!raw.includes("TODO: ship the proxy"), "no original, at any depth");
      for (const e of body.events) {
        assert.equal(e.input?.original ?? null, null);
        assert.equal(e.output?.original ?? null, null);
        for (const s of e.output?.symbols ?? []) assert.equal(s.value, null);
      }
    }
    const page = await (await fetch(`http://127.0.0.1:${port}/api/home/agent?session=sess-page`)).text();
    const vm = JSON.parse(page) as { valuesShown: boolean };
    assert.equal(vm.valuesShown, false);
    assert.ok(!page.includes("# Notes: ship it"), "the masked item stays masked signed out");
    assert.ok(!page.includes("sk-live-e2e"));
    // Signed out, the server asked the arbiter for no value at all.
    const asked = arbiter.opLog.slice(before).filter((o) => o.startsWith("resolve=") || o.startsWith("desymbolize"));
    assert.deepEqual(asked, [], asked.join(","));
    // The live stream: each event is the projection too.
    const ac = new AbortController();
    const stream = await fetch(`http://127.0.0.1:${port}/api/stream?session=sess-nested`, { signal: ac.signal });
    const reader = stream.body!.getReader();
    let text = "";
    const until = Date.now() + 5000;
    while (!text.includes("event: append") && Date.now() < until) {
      const { value, done } = await reader.read();
      if (done) break;
      text += new TextDecoder().decode(value);
    }
    ac.abort();
    assert.match(text, /"valuesShown":false/);
    assert.ok(!text.includes("TODO: ship the proxy"));
    // Signed in (cookie and CSRF header), the same read carries the original.
    const signedIn = await (await fetch(`http://127.0.0.1:${port}/api/events?session=sess-nested`, { headers: CSRF_ADMIN })).text();
    assert.ok(signedIn.includes("TODO: ship the proxy"));
    assert.match(signedIn, /"valuesShown":true/);
  } finally {
    await server.close();
  }
});
