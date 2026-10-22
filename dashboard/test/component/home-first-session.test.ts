/**
 * home-first-session.test — Home after a fresh install's first sessions, end
 * to end (dashboard.md §4.25: "Agents, not sessions", the running state, and
 * who an ask names). Found 2026-10-05 on a live tour:
 *
 *   - one `mandu claude` that only read .env made Home say "3 agents are
 *     running": the arbiter's admin log and the net-guard's sessionless
 *     fallback were listed as "The agent" (and "1 send allowed by you", the
 *     reply filter's reveal counted as a send; Home's counts are the story's
 *     since `storyCounts`, pinned here for this session);
 *   - after that agent `/exit`ed and a second one started, both stayed under
 *     "Running now";
 *   - a send the second session (`mandu codex`) made of the same secret to
 *     the same host was asked as "Claude Code wants to send …": one queue row
 *     per (item, destination), named after its first session.
 *
 * The REAL DashboardServer over recorded event logs
 * (test/unit/view-model/first-session-fixture.ts) placed against the real
 * clock, in a FileEventSource whose policy snapshot reports the Secrets
 * posture and the approval queue (what the arbiter would report). The served
 * product page (index.html, home.js) runs in jsdom with its fetch bridged to
 * it.
 *
 * Axes: secrets (confidentiality ON, integrity OFF), as the served posture;
 * display only, no arbiter runs.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { rmSync, writeFileSync } from "node:fs";
import { JSDOM } from "jsdom";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import type { PolicySnapshot, VerdictEntry } from "../../src/policy-model.js";
import type { ManduEvent } from "../../src/event-model.js";
import { tmpDir } from "../unit/tmp-dir.js";
import { firstSessionEvents, adminLogEvents, netGuardLogEvents, FIRST_SESSION, STRIPE } from "../unit/view-model/first-session-fixture.js";
import { waitWhile } from "../unit/page-wait.js";
import { pageFetch } from "../unit/page-fetch.js";

const SECOND_SESSION = "1791164828-1616683";

/** A file source behind which the arbiter reports the Secrets posture and
 *  the given approval queue. */
class SecretsSource extends FileEventSource {
  constructor(dir: string, private readonly verdicts: VerdictEntry[] = []) {
    super(dir);
  }
  override async policySnapshot(): Promise<PolicySnapshot | null> {
    return {
      specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
      posture: { integrity: false, confidentiality: true },
      usage: { rules: [], sensitivePaths: [] },
      verdicts: this.verdicts,
    } as unknown as PolicySnapshot;
  }
}

interface Store { dir: string; server: DashboardServer; base: string }
const stores: Store[] = [];

async function store(logs: Record<string, ManduEvent[]>, verdicts: VerdictEntry[] = []): Promise<Store> {
  const dir = tmpDir("mandu-home-first-");
  for (const [id, events] of Object.entries(logs)) {
    writeFileSync(join(dir, `${id}.ndjson`), events.map((e) => JSON.stringify(e)).join("\n") + "\n");
  }
  const server = new DashboardServer({ source: new SecretsSource(dir, verdicts), configEnv: { MANDU_HOME: tmpDir("mandu-home-first-home-") }, log: () => {} });
  const s = { dir, server, base: `http://127.0.0.1:${await server.listen(0)}` };
  stores.push(s);
  return s;
}

let one: Store;
let two: Store;

before(async () => {
  const now = Date.now();
  const system = {
    "arbiter-admin": adminLogEvents({ startMs: now - 60_000 }),
    "net-guard": netGuardLogEvents({ startMs: now - 30_000 }),
  };
  // The first session, still running (its events end about 10 s ago).
  one = await store({ [FIRST_SESSION]: firstSessionEvents({ startMs: now - 20_000 }), ...system });
  // It `/exit`ed 15 s ago; a Codex session started since and asked to send
  // the same secret to the host the first one had been allowed once.
  two = await store(
    {
      [FIRST_SESSION]: firstSessionEvents({ startMs: now - 25_000, exited: true }),
      [SECOND_SESSION]: firstSessionEvents({ session: SECOND_SESSION, startMs: now - 12_000, codex: true }),
      ...system,
    },
    [{
      id: "egr-1", symbol: STRIPE, destination: "api.stripe.com", status: "pending",
      reason: "secret symbol (no-model) at unbound destination 'api.stripe.com' → human declassification required",
      count: 2, firstSeen: now - 20_000, lastSeen: now - 3_000, sessions: [FIRST_SESSION, SECOND_SESSION],
    } as VerdictEntry],
  );
});

after(async () => {
  for (const s of stores) {
    await s.server.close();
    rmSync(s.dir, { recursive: true, force: true });
  }
});

interface Home {
  verdict: string;
  sentence: string;
  window: { sessions: number; masked: number; secret: number; blocked: number; sent: number; waiting: number };
  agents: { id: string; agent: string; state: string }[];
  waiting: { id: string; sentence: { text: string }[] }[];
  history: { total: number };
  firstRun: unknown;
}

async function home(s: Store): Promise<Home> {
  const res = await pageFetch(`${s.base}/api/home`);
  assert.equal(res.status, 200);
  return (await res.json()) as Home;
}

/** The served product page in jsdom, its fetch bridged to the server; `fn`
 *  runs once `ready` holds, then the window closes. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function servedHome(s: Store, ready: (doc: any) => boolean, fn: (doc: any) => void): Promise<void> {
  const html = await (await pageFetch(`${s.base}/`)).text();
  const js = await (await pageFetch(`${s.base}/js/home.js`)).text();
  const dom = new JSDOM(html.replace(/<script type="module"[^>]*><\/script>/, ""), { url: `${s.base}/`, runScripts: "outside-only", pretendToBeVisual: true });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const w = dom.window as any;
  let closed = false;
  const gate = <T>(p: Promise<T>): Promise<T> =>
    p.then((v) => (closed ? new Promise<T>(() => {}) : v), (e) => (closed ? new Promise<T>(() => {}) : Promise.reject(e)));
  w.fetch = (url: string, { signal: _signal, ...init }: RequestInit = {}) =>
    gate(pageFetch(new URL(url, s.base).href, init).then(async (res) => {
      const body = await res.text();
      return { ok: res.ok, status: res.status, json: () => gate(Promise.resolve().then(() => JSON.parse(body))) };
    }));
  w.setInterval = () => 0;
  w.scrollTo = () => {};
  w.eval(js);
  try {
    const doc = w.document;
    await waitWhile(() => !ready(doc));
    fn(doc);
  } finally {
    closed = true;
    w.close();
  }
}

test("/api/home after one session that read .env: one agent, no system log as a row, no send counted", async () => {
  const h = await home(one);
  assert.equal(h.verdict, "secrets-only");
  assert.deepEqual(h.agents.map((a) => [a.id, a.agent, a.state]), [[FIRST_SESSION, "Claude Code", "running"]]);
  assert.match(h.sentence, /^One agent is running under Mandu\./);
  assert.equal(h.history.total, 1, "the system logs are not sessions in the history either");
  // The one masked secret's session is named, so Home's count opens it (§4.25 *The counts link where they point*).
  assert.deepEqual(h.window, { hours: 24, sessions: 1, counted: 1, masked: 1, secretsMasked: 1, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0,
    only: { secretsMasked: FIRST_SESSION, secretsEarly: null, blocked: null, sent: null } });
  assert.equal(h.firstRun, null);
});

test("the served Home: one row under Running now, the hero counts no send, and nothing says 'allowed by you'", async () => {
  await servedHome(one, (doc) => doc.querySelectorAll("#home-agents .row.agent").length > 0, (doc) => {
    assert.equal(doc.querySelectorAll("#home-agents .row.agent").length, 1);
    // Its count under its prompt, and when it started, though it counts
    // something (dashboard.md §4.25, Home's rows).
    const row = doc.querySelector("#home-agents .row.agent");
    assert.equal(row.querySelector(".agent-what > .agent-counts").textContent, "1 secret masked");
    assert.match(row.querySelector(".agent-when").textContent, /^started (just now|1 minute ago)$/, "it started 20 s before the server");
    assert.match(row.querySelector(".agent-when time").getAttribute("title"), /^[A-Z][a-z]{2} \d{1,2}(?:, \d{4})?, \d{2}:\d{2}$/);
    assert.equal(doc.getElementById("home-history").textContent, "History: 1 session");
    const facts = doc.getElementById("hero-facts").textContent;
    assert.match(facts, /1 secret masked before the AI saw it/);
    assert.doesNotMatch(facts, /items? masked|guarded/, "the session page's words, not the masked tokens'");
    assert.doesNotMatch(facts, /send|allowed/);
    const page = doc.getElementById("page-home").textContent;
    assert.doesNotMatch(page, /Network guard events|Admin log|The agent\b/);
    assert.doesNotMatch(page, /allowed by you/);
  });
});

test("/api/home after the first agent exited and a Codex one started: one running, and its ask is Codex's", async () => {
  const h = await home(two);
  const state = new Map(h.agents.map((a) => [a.id, a.state]));
  assert.equal(state.get(SECOND_SESSION), "waiting", "the Codex session's ask is waiting");
  assert.equal(state.get(FIRST_SESSION), "idle", "a recorded exit ends the session at once, not five minutes later");
  assert.deepEqual(h.agents.find((a) => a.id === SECOND_SESSION)!.agent, "Codex CLI");
  assert.equal(h.agents.length, 2);
  assert.equal(h.history.total, 2);
  assert.equal(h.waiting.length, 1);
  assert.match(h.waiting[0]!.sentence.map((p) => p.text).join(""), /^Codex CLI wants to send .*api\.stripe\.com/);
});

test("the served Approvals page names the Codex session's ask after Codex", async () => {
  await servedHome(two, (doc) => doc.querySelectorAll("#home-waiting .ask").length > 0, (doc) => {
    const ask = doc.querySelector("#home-waiting .ask .ask-sentence").textContent;
    assert.match(ask, /^Codex CLI wants to send/);
    assert.doesNotMatch(ask, /Claude Code/);
  });
});

test("an OpenClaw session: the page shows the person's question without OpenClaw's time envelope", async () => {
  // Found 2026-10-11 walking the first-session tour on OpenClaw: every
  // question on the session page read "[Sun 2026-10-11 05:20 GMT+9] What
  // is in .env?". OpenClaw puts that envelope before the typed text.
  const now = Date.now();
  const s = await store({ [FIRST_SESSION]: firstSessionEvents({ startMs: now - 25_000, exited: true, userPrefix: "[Sun 2026-10-11 05:20 GMT+9] " }) });
  const page = (await (await pageFetch(`${s.base}/api/home/agent?session=${FIRST_SESSION}`)).json()) as { title: string | null; story: { prompt: string | null }[] };
  const prompts = page.story.map((t) => t.prompt).filter((p): p is string => p !== null);
  assert.deepEqual(prompts, ["What is in .env?"]);
  assert.doesNotMatch(JSON.stringify(page.story), /GMT\+9/);
});

test("a session with no prompt: Home and its page give no title, never the launcher's posture line", async () => {
  // Found 2026-10-05 on a live tour: a `mandu claude` that never reached the
  // model was titled "claude launch: 7 rung(s) live [exec-wrap, …]" under
  // Earlier. The inspector keeps that label; the product pages say there was
  // no prompt.
  const now = Date.now();
  const noPrompt = firstSessionEvents({ startMs: now - 25_000, exited: true }).filter((e) => e.kind !== "tllm_call");
  const s = await store({ [FIRST_SESSION]: noPrompt });
  const sessions = (await (await pageFetch(`${s.base}/api/sessions`)).json()) as { sessions: { id: string; label: string | null; labelFrom?: string }[] };
  const ref = sessions.sessions.find((r) => r.id === FIRST_SESSION)!;
  assert.match(ref.label ?? "", /^claude launch: \d+ rung\(s\) live/, "the inspector still names it by its posture");
  assert.equal(ref.labelFrom, "posture");
  const h = (await home(s)) as unknown as { agents: { id: string; title: string | null }[] };
  assert.equal(h.agents.find((a) => a.id === FIRST_SESSION)!.title, null);
  const page = (await (await pageFetch(`${s.base}/api/home/agent?session=${FIRST_SESSION}`)).json()) as { title: string | null };
  assert.equal(page.title, null);
  await servedHome(s, (doc) => doc.querySelectorAll("#home-earlier .row.agent").length > 0, (doc) => {
    const row = doc.querySelector("#home-earlier .row.agent").textContent;
    assert.match(row, /No prompt reached the AI/);
    assert.doesNotMatch(doc.getElementById("page-home").textContent, /rung|launch:/);
  });
});

test("a read the kernel guard refused in a history holding a locked secret reads on the session page as a file decision, never \"a connection to the network\"", async () => {
  // Found 2026-10-11 walking the first-session tour on OpenCode: after
  // `mandu policy suggest` labelled deploy/staging.conf, the next launch's
  // page opened with "Mandu blocked a connection to the network": the guard
  // had refused OpenCode's own snapshot repository, which held the file from
  // the earlier session. The guard records its file decisions as net_action.
  const now = Date.now();
  const repo = "/home/u/.local/share/opencode/snapshot/global/f5f963614a1ab40ea426568fe3408c6b5559f85c";
  const s = await store({ [FIRST_SESSION]: firstSessionEvents({ startMs: now - 25_000, exited: true, gitLock: repo }) });
  const page = (await (await pageFetch(`${s.base}/api/home/agent?session=${FIRST_SESSION}`)).json()) as {
    story: { steps: { kind: string; icon?: string; sentence?: { text: string }[]; outcome?: string; note?: string | null; why?: unknown }[] }[];
  };
  const said = (st: { sentence?: { text: string }[] }): string => (st.sentence ?? []).map((p) => p.text).join("");
  const steps = page.story.flatMap((t) => t.steps).filter((st) => st.kind === "action");
  assert.ok(!steps.some((st) => /connection to/.test(said(st))), steps.map(said).join("\n"));
  // OpenCode's own snapshot history is said as what it is, and the note
  // says what really happens (never prepared: it comes back; K15).
  const lock = steps.find((st) => said(st).startsWith("Mandu kept OpenCode from reading its own snapshot history"));
  assert.ok(lock, steps.map(said).join("\n"));
  assert.equal(said(lock!), "Mandu kept OpenCode from reading its own snapshot history (its undo), which holds a file you marked secret, in …/opencode/snapshot/global/f5f963614a1ab40ea426568fe3408c6b5559f85c");
  assert.equal(lock!.icon, "file");
  assert.equal(lock!.outcome, "blocked");
  assert.match(lock!.note ?? "", /^Nothing needs doing\. .*comes back in each session where OpenCode reads that history\. To stop it, remove that folder outside Mandu/);
  assert.doesNotMatch(lock!.note ?? "", /next launch prepares/);
  assert.equal(lock!.why, undefined, "no host-shaped why");
});

test("a connect the guard refused to a Unix socket outside the session reads on the session page as a local program's socket, never \"a connection to the network\"", async () => {
  // Found 2026-10-11 walking the first-session tour: Claude Code, started
  // inside tmux, ran `tmux`; the guard refused its server's socket (a
  // program outside Mandu that can start commands), and the page said
  // "Mandu blocked a connection to the network".
  const now = Date.now();
  const sock = "/tmp/tmux-1007/default";
  const s = await store({ [FIRST_SESSION]: firstSessionEvents({ startMs: now - 25_000, exited: true, unixRefusal: sock }) });
  const page = (await (await pageFetch(`${s.base}/api/home/agent?session=${FIRST_SESSION}`)).json()) as {
    story: { steps: { kind: string; icon?: string; sentence?: { text: string }[]; outcome?: string; note?: string | null; why?: unknown }[] }[];
  };
  const said = (st: { sentence?: { text: string }[] }): string => (st.sentence ?? []).map((p) => p.text).join("");
  const steps = page.story.flatMap((t) => t.steps).filter((st) => st.kind === "action");
  assert.ok(!steps.some((st) => /connection to|the network/.test(said(st))), steps.map(said).join("\n"));
  const refused = steps.filter((st) => said(st).startsWith("Mandu kept the AI's command tmux"));
  assert.ok(refused.length >= 1, steps.map(said).join("\n"));
  assert.equal(said(refused[0]!), `Mandu kept the AI's command tmux from reaching a local program's socket: ${sock}`);
  assert.equal(refused[0]!.icon, "run");
  assert.equal(refused[0]!.outcome, "blocked");
  assert.match(refused[0]!.note ?? "", /runs outside Mandu/);
  assert.equal(refused[0]!.why, undefined, "no host-shaped why");
});
