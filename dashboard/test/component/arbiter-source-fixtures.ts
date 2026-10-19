/**
 * arbiter-source-fixtures — the shared harness for the ArbiterEventSource e2e
 * suites (split out of the former arbiter-source.test.ts):
 *   - arbiter-source-sessions.test.ts  listSessions / readEvents, memoization,
 *                                      scale + fault isolation (§1, §5, §6)
 *   - arbiter-source-reveal.test.ts    desymbolize / resolveSymbol and the
 *                                      /api/events + /api/home/agent reveals (§1b)
 *   - arbiter-source-stream.test.ts    subscribe + the /api/stream relay (§2, §3)
 *   - arbiter-source-delete.test.ts    deleteSession over IPC + HTTP (§4)
 *
 * Mandu-new test code (NO reference origin). The arbiter sibling implements the
 * `sessions`/`events`/`subscribe` event ops (dashboard.md §3.1); this module
 * stands up a self-contained MOCK arbiter server on a temp Unix socket that
 * speaks that exact contract:
 *
 *   - `sessions`  req {op:"sessions"} → {sessions:[{sessionId,count,firstTs,lastTs}]}
 *   - `events`    req {op:"events", sessionId, sinceSeq?} → {events: ManduEvent[]}
 *                 (seq-ordered, seq > sinceSeq)
 *   - `subscribe` req {op:"subscribe", sessionId, sinceSeq?} on a DEDICATED
 *                 connection → backlog frames then live frames, each
 *                 {ok:true, result:{type:"event", event}}, until the client closes.
 *
 * Not a .test.ts so the runner glob skips it.
 */

import { createServer, type Server, type Socket } from "node:net";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { EventEmitter } from "node:events";

import { ArbiterEventSource } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";
import { tmpDir } from "../unit/tmp-dir.js";

// ── Canned events ─────────────────────────────────────────────────────────────

export function ev(over: Partial<ManduEvent> & Pick<ManduEvent, "id" | "seq" | "ts">): ManduEvent {
  return {
    sessionId: "sess-live",
    turn: 0,
    callId: null,
    parentId: null,
    kind: "tllm_call",
    view: "AgentView",
    boundary: "model_context",
    emitter: "anthropic-proxy",
    input: null,
    output: null,
    invariant: { violatedInvariant: false },
    ...over,
  } as ManduEvent;
}

export const HEALTHY: ManduEvent[] = [
  ev({ id: "e0", seq: 0, ts: "2026-06-14T10:00:00.000Z", kind: "tllm_call" }),
  ev({ id: "e1", seq: 1, ts: "2026-06-14T10:00:01.000Z", kind: "tool_use", callId: "c1" }),
  ev({ id: "e2", seq: 2, ts: "2026-06-14T10:00:02.000Z", kind: "tool_result", callId: "c1" }),
];

export const VIOLATED: ManduEvent[] = [
  ev({ id: "v0", sessionId: "sess-bad", seq: 0, ts: "2026-06-14T09:00:00.000Z" }),
  ev({
    id: "v1",
    sessionId: "sess-bad",
    seq: 1,
    ts: "2026-06-14T09:00:01.000Z",
    kind: "tool_result",
    invariant: { violatedInvariant: true, detail: "un-symbolized untrusted reached context" },
  }),
];

// A session whose events carry a batchId (sessions run together share it, so the
// sidebar groups them). Earliest ts so it stays last in the recency order.
export const BATCHED: ManduEvent[] = [
  ev({ id: "b0", sessionId: "sess-batch", seq: 0, ts: "2026-06-14T08:00:00.000Z", batchId: "run-7" }),
];

export const LIVE_EVENT = ev({ id: "e3", seq: 3, ts: "2026-06-14T10:00:03.000Z", kind: "tllm_call" });

// A session whose DELIVERED reply carries a NESTED symbol chain (the fs-sync
// twin-Read double-symbolization): the outer symbol's event-carried value still
// contains the inner fs-sync symbol, whose original lives ONLY in the arbiter
// symbol table. Drives the §4.2c delivery-zone deep reveal e2e.
export const OUTER_SYM = "$MDU:Read[f435]";
export const INNER_SYM = "$MDU:Read[d9ce].notes.md";
export const TWIN_CONTENT = `1\t${INNER_SYM}\n2\t`;
export const RAW_NOTES = "# Project notes\n\nTODO: ship the proxy.\n";
/** The mock arbiter's symbol table backing its `desymbolize` op. */
export const SYMBOL_TABLE: Record<string, string> = { [OUTER_SYM]: TWIN_CONTENT, [INNER_SYM]: RAW_NOTES };

export const NESTED: ManduEvent[] = [
  ev({ id: "n0", sessionId: "sess-nested", seq: 0, ts: "2026-06-14T07:00:00.000Z", kind: "tool_use", callId: "c1",
    input: { symbolized: 'Read({"file_path":"/ws/notes.md"})', original: null, differs: false, symbols: [] } }),
  ev({ id: "n1", sessionId: "sess-nested", seq: 1, ts: "2026-06-14T07:00:01.000Z", kind: "tool_result", callId: "c1",
    output: { symbolized: OUTER_SYM, original: TWIN_CONTENT, differs: true,
      symbols: [{ name: OUTER_SYM, tool: "Read", field: null, origin: "/agentview/notes.md", value: TWIN_CONTENT }] },
    policy: { trust: "UNTRUSTED" } } as never),
  ev({ id: "n2", sessionId: "sess-nested", seq: 2, ts: "2026-06-14T07:00:02.000Z", kind: "tllm_call",
    input: { symbolized: "▸ user\nRead notes.md and summarize.", original: null, differs: false, symbols: [] },
    output: { symbolized: `The file contents are: ${OUTER_SYM}`, original: null, differs: false, symbols: [] } }),
];

/** The product page's "What happened" (§4.25b): a Read whose result the
 *  events carry ONLY as a token (the value lives in the arbiter table), a
 *  twin inside it that the fs-sync seed recorded, and a SECRET beside it,
 *  plus the network gate's block. The page must fetch values one level at a
 *  time (the shallow `resolve` op) and never ask for the secret. */
export const PAGE_OUTER = "$MDU:Read[a0a0]";
export const PAGE_INNER = "$MDU:Read[b1b1].notes";
export const PAGE_SECRET = "$MDU:anymodel_Read[c2c2].env";
export const PAGE_TABLE: Record<string, string> = {
  [PAGE_OUTER]: `1\t${PAGE_INNER}\n2\t${PAGE_SECRET}`,
  [PAGE_INNER]: "# Notes: ship it",
  [PAGE_SECRET]: "API_KEY=sk-live-e2e",
};
export const PAGE: ManduEvent[] = [
  ev({ id: "p0", sessionId: "sess-page", seq: 0, ts: "2026-06-14T05:00:00.000Z", kind: "symbolize", emitter: "fs-sync" as never,
    output: { symbolized: `${PAGE_INNER} ${PAGE_SECRET}`, original: null, differs: true, symbols: [
      { name: PAGE_INNER, tool: "Read", field: "notes", origin: "/ws/notes.md", value: null },
      { name: PAGE_SECRET, tool: "Read", field: "env", origin: "/ws/.env", value: null, confidentiality: "any-model" },
    ] } }),
  ev({ id: "p1", sessionId: "sess-page", seq: 1, ts: "2026-06-14T05:00:01.000Z", kind: "tool_use", callId: "cp",
    input: { symbolized: 'Read({"file_path":"/ws/notes.md"})', original: null, differs: false, symbols: [] } }),
  ev({ id: "p2", sessionId: "sess-page", seq: 2, ts: "2026-06-14T05:00:02.000Z", kind: "tool_result", callId: "cp",
    output: { symbolized: PAGE_OUTER, original: null, differs: true,
      symbols: [{ name: PAGE_OUTER, tool: "Read", field: null, origin: "/ws/notes.md", value: null }] },
    policy: { trust: "UNTRUSTED" } } as never),
  ev({ id: "p3", sessionId: "sess-page", seq: 3, ts: "2026-06-14T05:00:03.000Z", kind: "net_action", view: "HumanView",
    boundary: "network" as never, emitter: "net-proxy" as never, action: "blocked", destination: "evil.example" } as never),
  ev({ id: "p4", sessionId: "sess-page", seq: 4, ts: "2026-06-14T05:00:04.000Z", kind: "tllm_call",
    input: { symbolized: "▸ user\nRead notes.md and summarize.", original: null, differs: false, symbols: [] },
    output: { symbolized: "Done.", original: null, differs: false, symbols: [] } }),
];

/** The same page with its seed event a CLAIM (arbiter-human-plane.md §10.2:
 *  the arbiter got it where the agent's programs reach): the twin it names
 *  is not known to the session, so the page never asks for its value. */
export const CLAIMED_PAGE: ManduEvent[] = PAGE.map((e) => ({
  ...e, sessionId: "sess-claim", ...(e.id === "p0" ? { claimed: true as const } : {}),
}));

/** A Claude Code shell escape (`!cat ~/.ssh/github`) whose output the arbiter
 *  masked as a no-model secret: the page reads "You ran" and a secret chip. */
export const SHELL_SECRET = "$MDU:nomodel_Bash[d3d3]";
export const SHELL: ManduEvent[] = [
  ev({ id: "s0", sessionId: "sess-shell", seq: 0, ts: "2026-06-14T08:00:00.000Z", kind: "tllm_call",
    input: { symbolized: `▸ user\n<bash-input>cat ~/.ssh/github</bash-input>\n<bash-stdout>${SHELL_SECRET}</bash-stdout><bash-stderr></bash-stderr>`, original: null, differs: false, symbols: [] },
    output: { symbolized: "The key stayed masked.", original: null, differs: false, symbols: [] } }),
];

/** A session whose launcher recorded secrets mode (launch_posture.protection):
 *  the classified result below would INFER integrity on; the record wins. */
export const RECORDED_MODE: ManduEvent[] = [
  ev({ id: "m0", sessionId: "sess-mode", seq: 0, ts: "2026-06-14T06:00:00.000Z", kind: "launch_posture", view: "HumanView",
    boundary: "shell", emitter: "launcher", protection: { mode: "secrets", integrity: false, confidentiality: true, reported: true } } as never),
  ev({ id: "m1", sessionId: "sess-mode", seq: 1, ts: "2026-06-14T06:00:01.000Z", kind: "tool_use", callId: "c9",
    input: { symbolized: 'Bash({"command":"git status"})', original: null, differs: false, symbols: [] } }),
  ev({ id: "m2", sessionId: "sess-mode", seq: 2, ts: "2026-06-14T06:00:02.000Z", kind: "tool_result", callId: "c9",
    output: { symbolized: "master", original: "master", differs: false, symbols: [] },
    policy: { trust: "TRUSTED", reason: "trusted command" } } as never),
];

// ── Mock arbiter ───────────────────────────────────────────────────────────────

export interface MockArbiter {
  socketPath: string;
  /** Push a live event to every active subscribe stream for `sessionId`. */
  pushLive(sessionId: string, event: ManduEvent): void;
  /** Number of currently-open subscribe streams (for close-handle assertions). */
  subscriberCount(): number;
  /** Every op served, as `op` or `op:sessionId` — the memoization assertions
   *  count `events:` entries per listSessions. Reset by truncating in place. */
  opLog: string[];
  /** Sessions whose `events` op is NEVER answered (a wedged replay) — the
   *  non-fatal-per-session assertions. Mutate in place. */
  hang: Set<string>;
  close(): Promise<void>;
}

/** A minimal NDJSON Unix-socket server that speaks the arbiter event protocol. */
export function startMockArbiter(store: Record<string, ManduEvent[]>): Promise<MockArbiter> {
  const dir = tmpDir("mandu-mockarbiter-");
  const socketPath = join(dir, "arbiter.sock");
  // Per-session set of live subscribe sockets.
  const subscribers = new Map<string, Set<Socket>>();
  const bus = new EventEmitter();
  const opLog: string[] = [];
  const hang = new Set<string>();

  const server: Server = createServer((sock) => {
    sock.setEncoding("utf8");
    let buf = "";
    let isStream = false;
    let streamSession = "";

    const writeFrame = (obj: unknown): void => {
      sock.write(JSON.stringify(obj) + "\n");
    };

    sock.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim() === "") continue;
        let req: { id?: unknown; op?: string; sessionId?: string; sinceSeq?: number };
        try {
          req = JSON.parse(line);
        } catch {
          continue;
        }
        opLog.push(req.sessionId ? `${req.op}:${req.sessionId}` : String(req.op));
        if (req.op === "hello") {
          // The human plane (arbiter-human-plane.md): the real arbiter names
          // its human socket here and serves sessions/events/subscribe/
          // desymbolize/resolve only there. This mock plays both sockets.
          writeFrame({ id: req.id, ok: true, result: { pid: process.pid, humanSock: socketPath } });
        } else if (req.op === "sessions") {
          const sessions = Object.entries(store).map(([sessionId, events]) => ({
            sessionId,
            count: events.length,
            firstTs: events.length ? events[0]!.ts : null,
            lastTs: events.length ? events[events.length - 1]!.ts : null,
          }));
          writeFrame({ id: req.id, ok: true, result: { sessions } });
        } else if (req.op === "events") {
          if (hang.has(req.sessionId ?? "")) continue; // wedged: no reply, ever
          const all = store[req.sessionId ?? ""] ?? [];
          const since = req.sinceSeq;
          const events = (since === undefined ? all : all.filter((e) => e.seq > since))
            .slice()
            .sort((a, b) => a.seq - b.seq);
          writeFrame({ id: req.id, ok: true, result: { events } });
        } else if (req.op === "deleteSession") {
          // The arbiter's observability delete (arbiter/ipc/server.ts
          // `deleteSession`): ANY session, live or test (2026-07-11 — the
          // original test-only refusal was dropped at the user's request);
          // unknown sessions error, otherwise drop the session from the store.
          const sid = req.sessionId ?? "";
          if (!store[sid]) {
            writeFrame({ id: req.id, ok: false, error: `unknown session: ${sid}` });
          } else {
            delete store[sid];
            writeFrame({ id: req.id, ok: true, result: { ok: true } });
          }
        } else if (req.op === "desymbolize") {
          // The arbiter's DEEP (fixpoint) egress op — resolve nested chains to
          // the original, leave unknown symbols literal (arbiter/ipc/server.ts).
          let text = String((req as { text?: unknown }).text ?? "");
          for (let i = 0; i < 8; i++) {
            const next = text.replace(/\$MDU:\w+\[\w+\](?:\.\w+)*/g, (m) => SYMBOL_TABLE[m] ?? m);
            if (next === text) break;
            text = next;
          }
          writeFrame({ id: req.id, ok: true, result: { text } });
        } else if (req.op === "resolve") {
          // The arbiter's SHALLOW resolve (no `deep`): one level, nested
          // tokens stay tokens (arbiter/ipc/server.ts).
          const name = String((req as { symbol?: unknown }).symbol ?? "");
          opLog.push(`resolve=${name}`);
          writeFrame({ id: req.id, ok: true, result: { value: (req as { deep?: unknown }).deep ? null : (PAGE_TABLE[name] ?? SYMBOL_TABLE[name] ?? null) } });
        } else if (req.op === "subscribe") {
          // Dedicated stream connection. Emit backlog frames, then register for
          // live frames until the client closes the socket.
          isStream = true;
          streamSession = req.sessionId ?? "";
          const all = store[streamSession] ?? [];
          const since = req.sinceSeq;
          const backlog = since === undefined ? all : all.filter((e) => e.seq > since);
          for (const event of backlog) {
            writeFrame({ ok: true, result: { type: "event", event } });
          }
          let set = subscribers.get(streamSession);
          if (!set) {
            set = new Set();
            subscribers.set(streamSession, set);
          }
          set.add(sock);
          const onLive = (event: ManduEvent): void => {
            writeFrame({ ok: true, result: { type: "event", event } });
          };
          bus.on(`live:${streamSession}`, onLive);
          sock.once("close", () => {
            bus.off(`live:${streamSession}`, onLive);
            subscribers.get(streamSession)?.delete(sock);
          });
        } else {
          writeFrame({ id: req.id, ok: false, error: `unknown op: ${String(req.op)}` });
        }
      }
    });
    sock.on("error", () => {
      /* a client hangup mid-stream is expected; ignore */
    });
    void isStream;
    void streamSession;
  });

  return new Promise((resolve) => {
    server.listen(socketPath, () => {
      resolve({
        socketPath,
        pushLive(sessionId, event) {
          bus.emit(`live:${sessionId}`, event);
        },
        subscriberCount() {
          let n = 0;
          for (const set of subscribers.values()) n += set.size;
          return n;
        },
        opLog,
        hang,
        async close() {
          for (const set of subscribers.values()) for (const s of set) s.destroy();
          await new Promise<void>((res) => server.close(() => res()));
          rmSync(dir, { recursive: true, force: true });
        },
      });
    });
  });
}

// ── Shared fixtures ───────────────────────────────────────────────────────────

/** The shared mock arbiter (every canned session) and a source over it, which
 *  the fixture-backed suites start in `before` and close in `after`. */
export async function startSharedFixtures(): Promise<{ arbiter: MockArbiter; source: ArbiterEventSource }> {
  const arbiter = await startMockArbiter({
    "sess-live": [...HEALTHY], "sess-bad": [...VIOLATED], "sess-batch": [...BATCHED],
    "sess-nested": [...NESTED], "sess-mode": [...RECORDED_MODE], "sess-page": [...PAGE], "sess-shell": [...SHELL],
    "sess-claim": [...CLAIMED_PAGE],
  });
  const source = new ArbiterEventSource({ socketPath: arbiter.socketPath });
  return { arbiter, source };
}
