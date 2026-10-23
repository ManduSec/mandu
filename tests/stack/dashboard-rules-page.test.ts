/**
 * dashboard-rules-page e2e — the Rules page's row buttons (dashboard.md
 * §4.25c) through the PRODUCTION wiring: `makeApprovalsArbiter(dataSock,
 * () => ({ socketPath: adminSock }))` over a REAL ArbiterServer with a
 * file-backed law, the real ArbiterEventSource for the panel, a real
 * DashboardServer, and HTTP with the admin session.
 *
 * The row ids come from the SERVED panel (the compiled law: `~` expanded,
 * hosts lower-cased, default ports filled in) and every button is pressed by
 * id, so this proves the id → edit mapping against the arbiter's own
 * projection, not against a hand-written id:
 *   1. Block instead on an allow rule, and Remove on a trusted source and on a
 *      connection allowance, are tightenings: applied at once, on disk;
 *   2. Remove on a locked file loosens protection: the first press changes
 *      nothing and asks; pressing again with what was shown applies it, as
 *      the person's change on the Rules page, and Undo puts the lock back;
 *   3. a press without the confirmation, or with a stale one, never writes;
 *   0. every row's "Show in policy.yaml" finds its own lines on disk (§4.25g);
 *   4. a past answer is served naming the one piece of data it covers
 *      (§4.25e); Remove on it forgets it through the ADMIN channel, and the
 *      same send is asked again (never allowed) — the adapter forwards the op
 *      (parity), and the data socket refuses it.
 *
 * A second test (§4.25p, the use line): a policy.yaml rule that decides a
 * send is counted by the arbiter with its moment, and the SERVED Rules page,
 * its row opened, says "1 use, just now" with that moment, the clock time on
 * hover (the `secrets` axes, stated by the server options).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { PolicyPanelVM, YourRuleRowVM } from "../../dashboard/src/view-model/policy-panel.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("full"); // this suite states its axes (protection-modes.md §4)

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const EVIL = "https://evil.example/collect";
const LAW = `version: 1
paths:
  - { path: "~/mandu-rules-page-e2e/.env", level: no-model }
inbound:
  url: { default: UNTRUSTED, trustedList: [pypi.org] }
user_rules:
  - { id: r-0001, kind: release, to: { host: api.example.com }, mode: allow }
destinations:
  - { host: Registry.Example, connect: allow }
`;

test("Rules page buttons over the real arbiter: tighten at once, loosen only when confirmed, undo, forget an answer", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-rules-page-"));
  dirs.push(dir);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, LAW);
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: true, confidentiality: true, log: () => {},
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock);
  await gate.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc);
  assert.ok(wired.arbiter.forgetEgressApproval, "the production adapter forwards forgetEgressApproval");
  const server = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock }),
    approvalsArbiter: wired.arbiter,
    policyDocArbiter: wired.policyDoc,
    log: () => {},
    ...ADMIN_OPTS,
  });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const post = async (path: string, body?: unknown) => {
    const r = await pageFetch(base + path, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: r.status, body: (await r.json()) as Record<string, unknown> };
  };
  const rules = async (): Promise<YourRuleRowVM[]> => {
    const r = await pageFetch(`${base}/api/policy/panel`);
    return ((await r.json()) as { panel: PolicyPanelVM }).panel.yourRules ?? [];
  };
  const row = async (kind: string): Promise<YourRuleRowVM> => {
    const found = (await rules()).find((r) => r.kind === kind);
    assert.ok(found, `a ${kind} row is served`);
    return found!;
  };
  const press = (id: string, action: string, expected?: unknown) => post("/api/policy/rules/change", { id, action, ...(expected !== undefined ? { expected } : {}) });

  try {
    // 0. "Show in policy.yaml" (§4.25g): every served row id finds its own
    //    lines in the file on disk, the compiled lock id (`~` expanded)
    //    included; read-only, a GET with no admin header.
    const source = async (id: string) => (await (await pageFetch(`${base}/api/policy/rules/source?id=${encodeURIComponent(id)}`)).json()) as { found: boolean; start?: number; lines?: string[]; mark?: number[]; path?: string };
    const law = LAW.split("\n");
    for (const r of await rules()) {
      const got = await source(r.id);
      assert.equal(got.found, true, `${r.id} is found in policy.yaml`);
      assert.equal(got.path, policyPath);
      assert.deepEqual(got.lines, law.slice(got.start! - 1, got.start! - 1 + got.lines!.length), `${r.id}: the file's own lines, numbered as on disk`);
    }
    const lockRow = (await rules()).find((r) => r.kind === "lock")!;
    assert.ok(!lockRow.id.includes("~"), "the row carries the compiled path");
    assert.match((await source(lockRow.id)).lines!.join("\n"), /~\/mandu-rules-page-e2e\/\.env/, "…and the lines show what the person wrote");
    assert.equal((await source("r-9999")).found, false);

    // 1. Tightenings apply at once.
    const allow = await row("release-allow");
    assert.deepEqual(allow.actions, { remove: true, flip: "block" });
    const flip = await press(allow.id, "block");
    assert.equal(flip.status, 200, JSON.stringify(flip.body));
    assert.equal(flip.body.applied, true);
    assert.equal((await row("release-block")).id, "r-0001", "the same rule, now blocking");

    const pypi = await row("trusted-origin");
    const r2 = await press(pypi.id, "remove");
    assert.equal(r2.status, 200, JSON.stringify(r2.body));
    assert.ok(!(await rules()).some((r) => r.kind === "trusted-origin"));

    const reg = await row("connect-allow");
    assert.equal(reg.id, "connect:tcp:registry.example:443", "the compiled id");
    const r3 = await press(reg.id, "remove");
    assert.equal(r3.status, 200, JSON.stringify(r3.body));
    assert.doesNotMatch(readFileSync(policyPath, "utf8"), /Registry\.Example/, "the raw entry is gone from the file");

    // 2 + 3. A loosening asks, and only a confirmed press writes.
    const lock = await row("lock");
    assert.equal(lock.subject, join(homedir(), "mandu-rules-page-e2e/.env"), "the served row carries the expanded path");
    const before = readFileSync(policyPath, "utf8");
    const ask = await press(lock.id, "remove");
    assert.equal(ask.status, 200, JSON.stringify(ask.body));
    assert.equal(ask.body.confirm, true);
    assert.ok(Array.isArray(ask.body.expected) && (ask.body.expected as unknown[]).length > 0);
    assert.equal(readFileSync(policyPath, "utf8"), before, "asking writes nothing");
    const stale = await press(lock.id, "remove", []);
    assert.equal(stale.status, 409, "a press confirming less than it loosens is refused");
    assert.equal(readFileSync(policyPath, "utf8"), before);
    const done = await press(lock.id, "remove", ask.body.expected);
    assert.equal(done.status, 200, JSON.stringify(done.body));
    assert.equal(done.body.applied, true);
    assert.doesNotMatch(readFileSync(policyPath, "utf8"), /mandu-rules-page-e2e/);
    const history = (await (await pageFetch(`${base}/api/policy/changes?limit=5`)).json()) as { changes: Array<{ id: string; sentence: string }> };
    assert.equal(history.changes[0]!.sentence, "You changed a rule on the Rules page");
    assert.equal(history.changes[0]!.id, done.body.changeId);
    const undo = await post(`/api/policy/changes/${encodeURIComponent(String(done.body.changeId))}/undo`);
    assert.equal(undo.status, 200, JSON.stringify(undo.body));
    assert.match(readFileSync(policyPath, "utf8"), /mandu-rules-page-e2e/, "Undo puts the lock back");

    // 4. Forget a past answer: the same send is asked again, never allowed.
    const symbol = await gate.symbolize({ tool: "WebFetch", field: "text", value: "rules-page-forget-canary", origin: "https://docs.example/guide" });
    const deny = await gate.desymbolizationDecision({ symbol, boundary: "network", destination: EVIL });
    const approvalId = (deny as { approvalId?: string }).approvalId!;
    assert.ok(approvalId);
    assert.equal((await post(`/api/egress/approvals/${approvalId}/forget`)).status, 409, "a pending ask is not forgotten");
    assert.equal((await post(`/api/egress/approvals/${approvalId}/approve`)).status, 200);
    assert.equal((await gate.desymbolizationDecision({ symbol, boundary: "network", destination: EVIL })).allow, true);
    // §4.25e: the served answer row names the one piece of data it covers
    // (the arbiter's read-time source), never the value.
    const panel = ((await (await pageFetch(`${base}/api/policy/panel`)).json()) as { panel: PolicyPanelVM }).panel;
    const answer = panel.queue.find((q) => q.id === approvalId);
    assert.equal(answer?.plain.reach, "sending only what was fetched from docs.example/guide");
    assert.doesNotMatch(JSON.stringify(panel), /rules-page-forget-canary/, "provenance only, never the value");
    const forgot = await post(`/api/egress/approvals/${approvalId}/forget`);
    assert.equal(forgot.status, 200, JSON.stringify(forgot.body));
    const again = await gate.desymbolizationDecision({ symbol, boundary: "network", destination: EVIL });
    assert.equal(again.allow, false, "a forgotten allow is not an allow");
    assert.equal((again as { requiresApproval?: boolean }).requiresApproval, true, "it asks again");
    await assert.rejects(() => gate.forgetEgressApproval((again as { approvalId: string }).approvalId), /admin-only/, "the data socket cannot forget");
  } finally {
    await server.close();
    wired.close();
    gate.close();
    admin.close();
    await arbiter.close();
  }
});

test("an opened rule on the served Rules page says when it last decided something (real arbiter, §4.25p)", { timeout: 120_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-rules-used-"));
  dirs.push(dir);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, LAW);
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock);
  await gate.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc);
  const server = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock }),
    approvalsArbiter: wired.arbiter,
    policyDocArbiter: wired.policyDoc,
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  const served = async (): Promise<YourRuleRowVM> => {
    const r = ((await (await pageFetch(`${base}/api/policy/panel`)).json()) as { panel: PolicyPanelVM }).panel.yourRules ?? [];
    const found = r.find((x) => x.id === "r-0001");
    assert.ok(found, "the allow rule is served");
    return found!;
  };
  try {
    assert.equal((await served()).hits, 0, "not used yet");
    // The rule decides one send: fetched data to api.example.com.
    const before = Date.now();
    const symbol = await gate.symbolize({ tool: "WebFetch", field: "text", value: "rules-used-canary", origin: "https://docs.example/guide" });
    const sent = await gate.desymbolizationDecision({ symbol, boundary: "network", destination: "https://api.example.com/upload" });
    assert.equal(sent.allow, true, JSON.stringify(sent));
    const row = await served();
    assert.equal(row.hits, 1, "the arbiter counted the decision");
    assert.ok(typeof row.lastHit === "number" && row.lastHit >= before - 1_000 && row.lastHit <= Date.now(), `with its moment: ${row.lastHit}`);

    const rowOf = (doc: any) => ([...doc.querySelectorAll("#rules-list .row")] as any[]).find((r) => /api\.example\.com/.test(r.textContent)); // eslint-disable-line @typescript-eslint/no-explicit-any
    await servedProductPage(base, "/rules", (doc) => rowOf(doc) !== undefined, async (doc) => {
      rowOf(doc).querySelector(".file-more").click();
      const detail = rowOf(doc).nextElementSibling;
      const line = ([...detail.querySelectorAll(".dim")] as any[]).find((d) => /\buses?\b/.test(d.textContent)); // eslint-disable-line @typescript-eslint/no-explicit-any
      assert.ok(line, `the opened rule has a use line: ${detail.textContent}`);
      assert.equal(line.textContent, "1 use, just now");
      const at = line.querySelector("time.ago");
      const ms = Date.parse(at.getAttribute("datetime"));
      assert.ok(Date.now() - ms < 60_000 && ms >= before - 1_000, `a moment within the last minute: ${at.getAttribute("datetime")}`);
      assert.equal(ms, row.lastHit, "the moment the arbiter keeps");
      assert.match(at.getAttribute("title"), /^[A-Z][a-z]{2} \d{1,2}(?:, \d{4})?, \d{2}:\d{2}$/, "the clock time on hover");
      assert.doesNotMatch(doc.body.textContent ?? "", /rules-used-canary|\$MDU/, "the page carries neither the value nor a token");
    }, { headers: { Cookie: ADMIN_COOKIE } });
  } finally {
    await server.close();
    wired.close();
    gate.close();
    await arbiter.close();
  }
});
