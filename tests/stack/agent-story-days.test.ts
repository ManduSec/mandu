/**
 * agent-story-days — a session that runs past midnight names the day where
 * its turns change day, across the REAL components (dashboard.md §4.25, the
 * per-agent page, *A session on more than one day names its days*).
 * Mandu-new.
 *
 * A turn's head showed only its clock time: a session left open overnight
 * showed "23:50" and then "00:10" with nothing to say a day went by. Here a
 * real ArbiterServer runs at the `secrets` axes and the REAL anthropic-proxy
 * on its production client (`new ArbiterClientAdapter(data, human)`)
 * carries one session of three questions, the second reading a `.env` whose
 * key the proxy masks. The process clock is set back while each question
 * runs, to 23:50, 23:58 and 00:10 around yesterday's midnight in the
 * viewer's local time (TZ pinned east of UTC), so the real event store
 * records them then; it only moves forward, and it is the real clock again
 * before the page is read. A real DashboardServer over a real ArbiterEventSource serves it:
 *
 *   D1  /api/home/agent: the three turns, in order, with their times;
 *   D2  the served session page: a day line before the first turn and one
 *       before the third, naming each local day, and each turn's time a
 *       <time> whose tooltip names its day;
 *   D3  the oracle: no answer or drawn page carries the key's value, nor a
 *       token (`$MDU`) on the product side; the day lines carry only dates.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the served page; the stack supplies the real session.
 */
process.env.TZ = "Asia/Seoul"; // UTC+9: 23:50 there is 14:50 UTC, the same UTC day as 00:10

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { Readable } from "node:stream";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = `1791900000-${process.pid}`;
const VALUE = `sk_live_storyDaysCanary_${process.pid}_000000`;
const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
/** A local day as the page names it: "Friday, Oct 16", with the year when not this year. */
const dayWords = (d: Date) => `${WEEKDAYS[d.getDay()]}, ${MONTHS[d.getMonth()]} ${d.getDate()}${d.getFullYear() === new Date().getFullYear() ? "" : `, ${d.getFullYear()}`}`;
const pad = (k: number) => String(k).padStart(2, "0");
const dayKey = (d: Date) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

test("a session whose turns cross midnight draws a day line before the first turn of each day on the served page, on the real stack, and no value is shown (secrets axes, explicit)", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-story-days-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  // No `extensions`: the product page only, as the shipped package.
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }), configEnv: { MANDU_HOME: join(tmp, "home") }, log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const seen: string[] = [];
  const replies: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = replies.shift() ?? buildTextSse("Done.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  const ask = async (messages: unknown[], reply?: string) => {
    if (reply) replies.push(reply);
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
  };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the secret value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  // The process clock, set back by `back` ms: `Date.now()` and `new Date()`
  // for every component in this process. Set only forward, then put back.
  const RealDate = Date;
  let back = 0;
  class ShiftedDate extends RealDate {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    constructor(...a: any[]) { if (a.length) super(...(a as [number])); else super(RealDate.now() - back); }
    static override now(): number { return RealDate.now() - back; }
  }
  // Yesterday's local midnight (always behind the clock, whenever this
  // runs): the turns at 23:50 and 23:58 before it, and 00:10 after it.
  const midnight = new RealDate();
  midnight.setHours(0, 0, 0, 0);
  midnight.setDate(midnight.getDate() - 1);
  const at = (minutes: number) => new RealDate(midnight.getTime() + minutes * 60_000);
  const times = [at(-10), at(-2), at(10)];
  assert.notEqual(dayKey(times[0]!), dayKey(times[2]!), "the turns cross the viewer's midnight");
  assert.equal(times[0]!.toISOString().slice(0, 10), times[2]!.toISOString().slice(0, 10), "but not UTC's: a page in UTC days would draw no line");
  try {
    const q1 = { role: "user", content: "Start the nightly build." };
    const q2 = { role: "user", content: "What is in .env?" };
    const q3 = { role: "user", content: "Is the build done?" };
    const read = { role: "assistant", content: [{ type: "tool_use", id: "toolu_sd_0", name: "Read", input: { file_path: env } }] };
    const result = { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_sd_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] };
    const turns: Array<() => Promise<void>> = [
      () => ask([q1], buildTextSse("Started.", { deltas: 1 })),
      async () => {
        await ask([q1, { role: "assistant", content: "Started." }, q2], buildToolUseSse({ id: "toolu_sd_0", name: "Read", input: { file_path: env } }));
        await ask([q1, { role: "assistant", content: "Started." }, q2, read, result], buildTextSse("It holds a key.", { deltas: 1 }));
      },
      () => ask([q1, { role: "assistant", content: "Started." }, q2, read, result, { role: "assistant", content: "It holds a key." }, q3], buildTextSse("Yes.", { deltas: 1 })),
    ];
    globalThis.Date = ShiftedDate as DateConstructor;
    try {
      for (const [i, run] of turns.entries()) {
        back = RealDate.now() - times[i]!.getTime();
        await run();
        await new Promise((r) => setTimeout(r, 20));
      }
    } finally {
      globalThis.Date = RealDate;
    }
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    assert.ok((await human.events(SESSION)).length > 0, "the session's events are in the store");

    // ── D1: the served record ──
    let body = "";
    let vm: AgentPageVM | null = null;
    for (let i = 0; i < 200; i++) {
      const r = await pageFetch(`${base}/api/home/agent?session=${SESSION}`);
      assert.equal(r.status, 200);
      body = await r.text();
      vm = JSON.parse(body) as AgentPageVM;
      if (vm.found && vm.story.length === 3 && vm.secrets?.counts?.masked === 1) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(vm && vm.found, "the session is served");
    assert.equal(vm.secrets?.counts?.masked, 1, "the key was masked before the AI saw it");
    assert.deepEqual(vm.story.map((t) => t.prompt), ["Start the nightly build.", "What is in .env?", "Is the build done?"], "the three turns, in order");
    for (const [i, t] of vm.story.entries()) {
      const ms = t.ts ? Date.parse(t.ts) : NaN;
      assert.ok(ms >= times[i]!.getTime() && ms < times[i]!.getTime() + 60_000, `turn ${i + 1} at ${t.ts}, recorded when it ran (${times[i]!.toISOString()})`);
    }
    noValue(body, "/api/home/agent");
    const ids = vm.story.map((t) => t.id);

    // ── D2: the served page ──
    await servedProductPage(base, `/agents/${SESSION}`, (doc) => doc.querySelectorAll("#agent-story article.turn").length === 3, (doc) => {
      const story = doc.getElementById("agent-story");
      const order = ([...story.children] as El[]).filter((x) => x.matches("article.turn, .story-day"))
        .map((x) => (x.classList.contains("story-day") ? `day ${x.textContent}` : x.dataset.turnId));
      assert.deepEqual(order, [`day ${dayWords(times[0]!)}`, ids[0], ids[1], `day ${dayWords(times[2]!)}`, ids[2]], "a line before the first turn of each day");
      const lines = [...story.querySelectorAll(".story-day")] as El[];
      assert.deepEqual(lines.map((l) => l.querySelector("time").getAttribute("datetime")), [dayKey(times[0]!), dayKey(times[2]!)], "each the viewer's local day");
      for (const l of lines) {
        assert.match(l.textContent, /^[A-Z][a-z]+day, [A-Z][a-z]{2} \d{1,2}(?:, \d{4})?$/, "a date and nothing else");
        noValue(l.outerHTML, "a day line");
      }
      const heads = ([...story.querySelectorAll("article.turn > .turn-head > .time")] as El[]);
      assert.deepEqual(heads.map((t) => t.tagName), ["TIME", "TIME", "TIME"]);
      assert.deepEqual(heads.map((t) => t.textContent), ["23:50", "23:58", "00:10"], "the clock time, local");
      assert.deepEqual(heads.map((t) => t.title.replace(/, \d{4}/, "").replace(/,.*/, "")), times.map((d) => `${MONTHS[d.getMonth()]} ${d.getDate()}`), "the tooltip names the day");
      noValue(doc.body.textContent, "the rendered session page");
    });

    // ── D3: the oracle ──
    for (const route of ["/api/home", "/api/home/history", `/api/home/agent?session=${SESSION}`]) {
      noValue(await (await pageFetch(base + route)).text(), route);
    }
  } finally {
    await proxy.close();
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
