/**
 * answered-day.test — Approvals › Answered earlier lists the answers from a
 * chosen day back, across the REAL components (dashboard.md §4.25 *Go to a
 * day on Answered earlier*). Mandu-new.
 *
 * Until then Answered earlier was reachable past its newest 20 only by Show
 * more, or by a search when a word of the answer was remembered. Here an
 * older arbiter's store (its clock set back) holds two answers on each of
 * three days: today, two days ago and four days ago, each a program's read
 * of a secret file. A real ArbiterServer at the `secrets` axes runs on that
 * DB, and a product-only DashboardServer reads its queue over a real
 * ArbiterEventSource with the real admin-socket client behind its approval
 * routes, signed out:
 *
 *   G1  `GET /api/home/answered?before=<the start of the day after the
 *       middle one>` lists the four answers of the middle and the oldest
 *       day, newest first, `total` 4, `before.all` 6; without it all six;
 *   G2  the served `/approvals?day=<the middle day>` (TZ pinned to Seoul,
 *       no daylight saving time): the box holds the day, the read carried
 *       `before=`, the first heading is that day, no answer of today is
 *       drawn, the status line says "From … back"; Show the newest lists
 *       today's answers first again and empties the address;
 *   G3  the oracle: neither the route nor the drawn page carries a secret
 *       file's value or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the served page and the route; the stack supplies the real
 * answers they read.
 */
process.env.TZ = "Asia/Seoul"; // UTC+9, no daylight saving time

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { EgressApprovalStore } from "../../arbiter/policy/egress-approvals.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AnsweredPage } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const H = "d".repeat(64);
const VALUE = `answered_day_stack_canary_${process.pid}_01`;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The local day of `ms` as a heading's datetime says it. */
function dayKey(ms: number): string {
  const d = new Date(ms);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}
/** The start of the local day after `key` (the page's `before=`). */
function dayAfter(key: string): number {
  const [y, m, d] = key.split("-").map(Number);
  return new Date(y!, m! - 1, d! + 1).getTime();
}

test("Answered earlier goes to a day: the route and the served page list the answers from that day back, none newer, no value shown (real arbiter, dashboard; secrets axes, explicit)", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-answered-day-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const dbPath = join(tmp, "symbols.sqlite");

  // An older arbiter's answers, on three days: its clock set to each.
  const now = Date.now();
  const startOfToday = new Date(new Date(now).getFullYear(), new Date(now).getMonth(), new Date(now).getDate()).getTime();
  const noon = (back: number) => { const t = new Date(now); return new Date(t.getFullYear(), t.getMonth(), t.getDate() - back, 12).getTime(); };
  const days = [
    { name: "today", at: [Math.max(startOfToday + 1_000, now - 120_000), Math.max(startOfToday + 2_000, now - 60_000)] },
    { name: "mid", at: [noon(2), noon(2) + 3_600_000] },
    { name: "old", at: [noon(4), noon(4) + 3_600_000] },
  ];
  let clock = 0;
  const old = new EgressApprovalStore({ dbPath, now: () => clock });
  const ids = new Map<string, string>();
  for (const d of days) {
    d.at.forEach((t, i) => {
      const file = join(home, `${d.name}-${i}.env`);
      writeFileSync(file, `TOKEN=${VALUE}\n`);
      clock = t;
      const row = old.recordPending(`open:/usr/bin/ssh-add#${H}`, file, "ssh-add wants to read it", "s-old");
      old.resolve(row.id, false, "always");
      ids.set(`${d.name}-${i}`, row.id);
    });
  }
  old.close();
  const mid = dayKey(days[1]!.at[0]!);
  const bound = dayAfter(mid);

  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath, eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const approvalsArbiter: ApprovalsArbiter = {
    egressApprovals: (status) => admin.egressApprovals(status),
    resolveEgressApproval: (approvalId, approve, scope) => admin.resolveEgressApproval(approvalId, approve, scope),
  };
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter, fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home") }, log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries a secret file's value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  try {
    // ── G1: the route ────────────────────────────────────────────────────────
    const everyText = await (await pageFetch(`${base}/api/home/answered`)).text();
    const every = JSON.parse(everyText) as AnsweredPage;
    assert.deepEqual(every.rows.map((r) => r.id), ["today-1", "today-0", "mid-1", "mid-0", "old-1", "old-0"].map((k) => ids.get(k)), "every answer, newest first");
    const cutText = await (await pageFetch(`${base}/api/home/answered?before=${bound}`)).text();
    const cut = JSON.parse(cutText) as AnsweredPage;
    assert.deepEqual(cut.rows.map((r) => r.id), ["mid-1", "mid-0", "old-1", "old-0"].map((k) => ids.get(k)), "from the middle day back, nothing newer");
    assert.equal(cut.total, 4);
    assert.deepEqual(cut.before, { at: bound, all: 6 });

    // ── G2: the served page ─────────────────────────────────────────────────
    const rowIds = (doc: El) => ([...doc.querySelectorAll("#approvals-answered .row.answered")] as El[]).map((r) => r.dataset.id);
    await servedProductPage(base, `/approvals?day=${mid}`, (doc) => rowIds(doc).length === 4, async (doc) => {
      const w = doc.defaultView;
      assert.equal(doc.getElementById("answered-day").value, mid, "the box holds the day");
      assert.deepEqual(rowIds(doc), cut.rows.map((r) => r.id), "the list from the day back");
      assert.ok(!rowIds(doc).includes(ids.get("today-0")) && !rowIds(doc).includes(ids.get("today-1")), "no answer of today");
      const heads = [...doc.querySelectorAll("#approvals-answered .history-day time")] as El[];
      assert.equal(heads[0]?.getAttribute("datetime"), mid, "the first heading is the day");
      assert.equal(heads.length, 2, "the middle day and the oldest");
      assert.match(doc.getElementById("answered-count").textContent, /^From .+ back$/);
      assert.equal(doc.getElementById("answered-newest").hidden, false);
      noValue(doc.body.textContent ?? "", "the drawn Approvals page from a day");
      doc.getElementById("answered-newest").click();
      await waitWhile(() => rowIds(doc).length < 6);
      assert.deepEqual(rowIds(doc).slice(0, 2), [ids.get("today-1"), ids.get("today-0")], "Show the newest: today first again");
      assert.equal(w.location.search, "", "the address has no day");
      assert.equal(doc.getElementById("answered-day").value, "");
      noValue(doc.body.textContent ?? "", "the drawn Approvals page");
    });

    // ── G3: the oracle ───────────────────────────────────────────────────────
    noValue(everyText, "/api/home/answered");
    noValue(cutText, "/api/home/answered?before=");
  } finally {
    await dashboard.close();
    admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
