/**
 * pair — one agent connection and its Chrome connection
 * (docs/design/agents/devtools-relay.md §2.2). Mandu-new (no reference
 * origin).
 *
 * Agent → Chrome (in order, one at a time): a refused command is answered
 * with an error; a release command runs release.ts (later commands wait,
 * so an Enter the agent sends after typing lands after the text); any other
 * is forwarded under a relay-assigned id (the relay's own commands share the
 * id space, so they never collide with the agent's). Key events that could
 * be a placeholder typed a key at a time are held and answered at once
 * (typing.ts): the run is released like a whole insert, or forwarded as
 * sent, when it ends (a key that cannot extend it, another command, or
 * KEY_RUN_IDLE_MS of quiet). A run that becomes a placeholder LOOKALIKE is
 * refused on the key that closes its code (typing.ts `decide`): that key is
 * answered with the error, so the agent's typing command fails while it
 * types, and the run's remaining keys are dropped (§3.3). A placeholder's
 * hex code is checked on the same key (typing.ts `check`): the arbiter is
 * asked whether its base names a row (`placeholderKnown`, human plane), and
 * a no, or no answer, refuses that key the same way. A run refused when
 * it ends cannot be answered with the error any more (its keys were
 * answered as they came), so the refusal is kept and answers the agent's
 * next `Input.*` command instead, which is not sent (§3.3). Every
 * refusal is also reported to the arbiter (`relayNotice`, §3.4) before the
 * agent is answered, so the egress proxy tells the agent's model on its next
 * call even when the agent drops the error.
 *
 * Chrome → agent: an answer to the relay's own command goes to it and never
 * to the agent; everything else is masked (inbound.ts) and delivered in the
 * order Chrome sent it (each message's filter call starts on arrival; the
 * deliveries wait for each other). A withheld answer becomes an error; a
 * withheld event is dropped.
 */
import type { Arbiter, RelayNotice } from "./arbiter-client.js";
import { maskMessage } from "./inbound.js";
import { refusalMessage, refusedBecause } from "./policy.js";
import { checkTyped, refuseLookalikes, release, releaseText, type ReleaseDeps } from "./release.js";
import type { WsConnection } from "./ws-server.js";
import { addedSymbols, browserEvent, type BrowserAction, type BrowserEventFields } from "./events.js";
import { ShownPlaceholders } from "./shown.js";
import { findLookalikes, findSymbols } from "./symbols.js";
import { KeyRun, type KeyCommand, type KeyStep, type RunEnd } from "./typing.js";

/** An origin's host, or the origin as given. */
function hostOf(origin: string): string {
  try { return new URL(origin).host; } catch { return origin; }
}

/** The agent's messages can be large (a script's source); Chrome's answers
 *  come through Node's own client, which takes what Chrome sends. */
export const MAX_PAYLOAD = 256 * 1024 * 1024;
/** How long the relay waits for Chrome to answer its own command. */
export const INTERNAL_TIMEOUT_MS = 10_000;
/** The error code the relay answers with (Chrome's generic server error). */
export const RELAY_ERROR_CODE = -32000;
/** A held key run ends after this long without a command from the agent. */
export const KEY_RUN_IDLE_MS = 400;
/** How long a refusal's answer waits for the arbiter to take its notice
 *  (§3.4): long enough that the agent's next model call finds it, short
 *  enough that an arbiter gone slows a refusal only this much. */
export const NOTICE_WAIT_MS = 500;

export interface PairDeps {
  arbiter: Arbiter;
  session?: string;
  log?: (line: string) => void;
  /** The placeholders shown to the agent (one per relay; shown.ts). */
  shown?: ShownPlaceholders;
}

interface CdpMessage {
  id?: number;
  method?: string;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: Record<string, unknown>;
  sessionId?: string;
}

type Pending =
  | { kind: "agent"; agentId: number; method: string; sessionId?: string }
  | { kind: "internal"; resolve: (r: Record<string, unknown>) => void; reject: (e: Error) => void; timer: NodeJS.Timeout };

export class RelayPair {
  private readonly chrome: WebSocket;
  private readonly opened: Promise<void>;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();
  private outbound: Promise<void> = Promise.resolve();
  private inbound: Promise<void> = Promise.resolve();
  private closed = false;
  private readonly closeHandlers: Array<() => void> = [];
  private readonly log: (line: string) => void;
  private readonly keys = new KeyRun();
  private keyIdle: NodeJS.Timeout | null = null;
  private readonly shown: ShownPlaceholders;
  /** A key run's refusal the agent has not been told yet (§3.3). */
  private untold: string | null = null;

  constructor(private readonly agent: WsConnection, chromeUrl: string, private readonly deps: PairDeps) {
    this.log = deps.log ?? (() => {});
    this.shown = deps.shown ?? new ShownPlaceholders();
    // Node's built-in client (no extensions offered).
    this.chrome = new WebSocket(chromeUrl);
    this.opened = new Promise((resolve, reject) => {
      this.chrome.addEventListener("open", () => resolve(), { once: true });
      this.chrome.addEventListener("error", () => reject(new Error(`no DevTools endpoint at ${chromeUrl}`)), { once: true });
    });
    this.opened.catch((err: Error) => {
      this.log(`cdp-relay: Chrome refused the connection: ${err.message}`);
      this.close();
    });
    agent.onMessage((text) => {
      this.outbound = this.outbound.then(() => this.fromAgent(text)).catch((err: Error) => this.log(`cdp-relay: agent message: ${err.message}`));
    });
    this.chrome.addEventListener("message", (ev) => {
      // A binary frame is not a DevTools message; Chrome sends text.
      if (typeof ev.data === "string") this.fromChrome(ev.data);
    });
    agent.onClose(() => this.close());
    this.chrome.addEventListener("close", () => this.close());
  }

  onClose(fn: () => void): void {
    this.closeHandlers.push(fn);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.keyIdle !== null) clearTimeout(this.keyIdle);
    for (const p of this.pending.values()) {
      if (p.kind === "internal") { clearTimeout(p.timer); p.reject(new Error("the connection closed")); }
    }
    this.pending.clear();
    try { this.agent.close(); } catch { /* already gone */ }
    try { this.chrome.close(); } catch { /* already gone */ }
    for (const fn of this.closeHandlers) fn();
  }

  private async fromAgent(text: string): Promise<void> {
    let msg: CdpMessage;
    try {
      msg = JSON.parse(text) as CdpMessage;
    } catch {
      return; // not a DevTools message; nothing to forward
    }
    if (typeof msg.id !== "number" || typeof msg.method !== "string") return;
    await this.opened.catch(() => undefined);
    if (this.closed) return;
    const why = refusedBecause(msg.method);
    if (why !== null) {
      this.log(`cdp-relay: refused ${msg.method} (${why})`);
      this.note("blocked", { method: msg.method, reason: why });
      return this.answerError(msg, refusalMessage(msg.method, why));
    }
    const typed = releaseText(msg.method, msg.params);
    const isKey = typed === null && msg.method === "Input.dispatchKeyEvent";
    // A key run refused after its keys were answered: the next input command
    // carries the refusal and is not sent (§3.3). No run holds while one is
    // untold (the run that set it has ended), so nothing held is lost.
    if (this.tell(msg)) return;
    let step = isKey ? this.keys.key(msg as KeyCommand) : null;
    if (step === null) await this.endRun(this.keys.end());
    else if (step.kind === "ended") await this.endRun(step.end);
    if (this.tell(msg)) return;
    if (step !== null && step.kind === "ended") step = this.keys.key(msg as KeyCommand);
    if (step !== null && step.kind === "decide") {
      this.armKeyIdle();
      return this.refuseNow(msg, step);
    }
    if (step !== null && step.kind === "check") return this.checkNow(msg, step);
    if (step !== null && step.kind === "hold") {
      this.armKeyIdle();
      return this.inOrder({ id: msg.id, result: {}, ...(msg.sessionId !== undefined ? { sessionId: msg.sessionId } : {}) });
    }
    if (typed !== null) {
      const sessionId = msg.sessionId;
      const outcome = await release(typed, this.releaseDeps(sessionId));
      const symbols = findSymbols(typed);
      if (outcome.kind === "refuse") {
        this.log(`cdp-relay: ${msg.method} refused: ${outcome.message}`);
        this.note("refused", { method: msg.method, symbols, reason: outcome.reason, ...(outcome.unknown !== undefined ? { unknown: outcome.unknown } : {}) });
        await this.report(outcome.notice);
        return this.answerError(msg, outcome.message);
      }
      this.log(`cdp-relay: released into ${outcome.origin}`);
      this.note("released", { method: msg.method, page: hostOf(outcome.origin), symbols });
      return this.inOrder({ id: msg.id, result: {}, ...(sessionId !== undefined ? { sessionId } : {}) });
    }
    const id = this.nextId++;
    this.pending.set(id, { kind: "agent", agentId: msg.id, method: msg.method, ...(msg.sessionId !== undefined ? { sessionId: msg.sessionId } : {}) });
    this.chrome.send(JSON.stringify({ ...msg, id }));
  }

  /** A key run that just became a lookalike (typing.ts `decide`): refused
   *  on this key, which the agent is answered with, so its typing command
   *  fails now; the run's keys are dropped when it ends (§3.3). */
  private async refuseNow(msg: CdpMessage, step: Extract<KeyStep, { kind: "decide" }>): Promise<void> {
    const outcome = await refuseLookalikes(findLookalikes(step.text), this.releaseDeps(step.sessionId));
    if (outcome.kind !== "refuse") return this.answerError(msg, "Mandu: nothing was typed"); // a lookalike is always refused
    this.log(`cdp-relay: typed keys refused as they came: ${outcome.message}`);
    this.note("refused", { method: "Input.dispatchKeyEvent", symbols: [], reason: outcome.reason, ...(outcome.unknown !== undefined ? { unknown: outcome.unknown } : {}) });
    await this.report(outcome.notice);
    this.answerError(msg, outcome.message);
  }

  /** A key run whose placeholder code just closed (typing.ts `check`): the
   *  arbiter asked whether its base names a row. Known, the key is held like
   *  any other. Unknown, or no answer (fail-closed), the key is answered
   *  with the refusal, so the agent's typing command fails while it types,
   *  and the run ends dropped (§3.3). The quiet timer waits for the answer:
   *  a slow arbiter does not end the run before it. */
  private async checkNow(msg: CdpMessage, step: Extract<KeyStep, { kind: "check" }>): Promise<void> {
    if (this.keyIdle !== null) { clearTimeout(this.keyIdle); this.keyIdle = null; }
    const outcome = await checkTyped(step.base, this.releaseDeps(step.sessionId));
    if (outcome === null || outcome.kind !== "refuse") {
      this.armKeyIdle();
      return this.inOrder({ id: msg.id, result: {}, ...(msg.sessionId !== undefined ? { sessionId: msg.sessionId } : {}) });
    }
    this.keys.refuse();
    this.log(`cdp-relay: typed keys refused as they came: ${outcome.message}`);
    this.note("refused", { method: "Input.dispatchKeyEvent", symbols: [step.base], reason: outcome.reason, ...(outcome.unknown !== undefined ? { unknown: outcome.unknown } : {}) });
    await this.report(outcome.notice);
    this.armKeyIdle();
    this.answerError(msg, outcome.message);
  }

  /** Answer an input command with the untold key-run refusal, if any. */
  private tell(msg: CdpMessage): boolean {
    if (this.untold === null || !(msg.method ?? "").startsWith("Input.")) return false;
    const told = this.untold;
    this.untold = null;
    this.log(`cdp-relay: ${msg.method} refused: it carries the key run's refusal`);
    this.answerError(msg, told);
    return true;
  }

  /** End the held key run when the agent goes quiet. */
  private armKeyIdle(): void {
    if (this.keyIdle !== null) clearTimeout(this.keyIdle);
    this.keyIdle = setTimeout(() => {
      this.keyIdle = null;
      this.outbound = this.outbound.then(() => this.endRun(this.keys.end())).catch((err: Error) => this.log(`cdp-relay: key run: ${err.message}`));
    }, KEY_RUN_IDLE_MS);
  }

  /** What a held key run came to: its placeholder released into the page
   *  (release.ts, as a whole insert), then the textless keys after it; or
   *  every held key forwarded as sent. Their answers went to the agent when
   *  they were held, so Chrome's are dropped. */
  private async endRun(end: RunEnd | null): Promise<void> {
    if (end === null) return;
    if (this.keyIdle !== null && !this.keys.holding) { clearTimeout(this.keyIdle); this.keyIdle = null; }
    const replay = (cmds: KeyCommand[]) => {
      for (const c of cmds) this.internal(c.method, c.params ?? {}, c.sessionId).catch(() => undefined);
    };
    if (end.kind === "forward") return replay(end.commands);
    // Refused as it came (refuseNow): none of its keys go, the agent was told.
    if (end.kind === "dropped") return replay(end.after);
    const outcome = await release(end.text, this.releaseDeps(end.sessionId));
    const symbols = findSymbols(end.text);
    if (outcome.kind === "refuse") {
      this.log(`cdp-relay: typed keys refused: ${outcome.message}`);
      this.note("refused", { method: "Input.dispatchKeyEvent", symbols, reason: outcome.reason, ...(outcome.unknown !== undefined ? { unknown: outcome.unknown } : {}) });
      await this.report(outcome.notice);
      this.untold = `${outcome.message} (the keys typed before this command; this command was not sent either)`;
    } else {
      this.log(`cdp-relay: typed keys released into ${outcome.origin}`);
      this.note("released", { method: "Input.dispatchKeyEvent", page: hostOf(outcome.origin), symbols });
    }
    replay(end.after);
  }

  /** release.ts's dependencies, on the agent's target `sessionId`. */
  private releaseDeps(sessionId: string | undefined): ReleaseDeps {
    return {
      arbiter: this.deps.arbiter,
      ...(this.deps.session !== undefined ? { session: this.deps.session } : {}),
      target: { send: (method, params) => this.internal(method, params, sessionId) },
      hints: (symbol) => this.shown.nearest(symbol),
    };
  }

  /** A command of the relay's own, on the agent's target. */
  private internal(method: string, params: Record<string, unknown>, sessionId: string | undefined): Promise<Record<string, unknown>> {
    if (this.closed) return Promise.reject(new Error("the connection closed"));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} timed out`));
      }, INTERNAL_TIMEOUT_MS);
      this.pending.set(id, { kind: "internal", resolve, reject, timer });
      this.chrome.send(JSON.stringify({ id, method, params, ...(sessionId !== undefined ? { sessionId } : {}) }));
    });
  }

  private fromChrome(text: string): void {
    let msg: CdpMessage;
    try {
      msg = JSON.parse(text) as CdpMessage;
    } catch {
      return;
    }
    let reply: Extract<Pending, { kind: "agent" }> | null = null;
    if (typeof msg.id === "number") {
      const p = this.pending.get(msg.id);
      if (p === undefined) return; // an answer to nothing the relay sent
      this.pending.delete(msg.id);
      if (p.kind === "internal") {
        clearTimeout(p.timer);
        if (msg.error !== undefined) p.reject(new Error(String(msg.error["message"] ?? "Chrome answered with an error")));
        else p.resolve(msg.result ?? {});
        return;
      }
      reply = p;
    }
    // Only the payload is page data; the envelope is the protocol's.
    const payload = reply !== null ? { result: msg.result, error: msg.error } : { params: msg.params };
    const masked = maskMessage(payload, {
      arbiter: this.deps.arbiter,
      ...(this.deps.session !== undefined ? { session: this.deps.session } : {}),
    });
    this.inbound = this.inbound.then(async () => {
      const v = await masked;
      const method = reply !== null ? reply.method : msg.method ?? "an event";
      if (v.kind === "withhold") this.note("withheld", { method, reason: v.reason });
      else {
        const symbols = addedSymbols(payload, v.message);
        if (symbols.length > 0) {
          this.note("masked", { method, symbols });
          this.shown.add(symbols);
        }
      }
      if (reply !== null) {
        const base = { id: reply.agentId, ...(reply.sessionId !== undefined ? { sessionId: reply.sessionId } : {}) };
        if (v.kind === "withhold") {
          this.log(`cdp-relay: withheld the answer to ${reply.method}: ${v.reason}`);
          return this.toAgent({ ...base, error: { code: RELAY_ERROR_CODE, message: `Mandu: the answer to ${reply.method} was withheld: ${v.reason}` } });
        }
        return this.toAgent({ ...base, ...(v.message as Record<string, unknown>) });
      }
      if (v.kind === "withhold") {
        this.log(`cdp-relay: dropped ${msg.method ?? "an event"}: ${v.reason}`);
        return;
      }
      this.toAgent({ method: msg.method, ...(v.message as Record<string, unknown>), ...(msg.sessionId !== undefined ? { sessionId: msg.sessionId } : {}) });
    });
  }

  /** One trace event (events.ts): best-effort, never awaited, a failure
   *  ignored (observability, off the security path). */
  private note(action: BrowserAction, fields: BrowserEventFields): void {
    let event: Record<string, unknown>;
    try { event = browserEvent(this.deps.session, action, fields); } catch { return; }
    this.deps.arbiter.emit(event).catch(() => undefined);
  }

  /** A refusal for the agent's model (§3.4): reported to the arbiter,
   *  waited for up to NOTICE_WAIT_MS, a failure ignored (the agent still
   *  gets the error; the notice is a hint, names only). */
  private async report(notice: RelayNotice): Promise<void> {
    let timer: NodeJS.Timeout | undefined;
    try {
      const sent = this.deps.arbiter.relayNotice(notice, this.deps.session).catch(() => undefined);
      await Promise.race([sent, new Promise<void>((resolve) => { timer = setTimeout(resolve, NOTICE_WAIT_MS); })]);
    } catch {
      /* best-effort */
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private answerError(msg: CdpMessage, message: string): void {
    this.inOrder({ id: msg.id, error: { code: RELAY_ERROR_CODE, message }, ...(msg.sessionId !== undefined ? { sessionId: msg.sessionId } : {}) });
  }

  /** An answer of the relay's own, after what Chrome sent before it. */
  private inOrder(msg: Record<string, unknown>): void {
    this.inbound = this.inbound.then(() => this.toAgent(msg));
  }

  private toAgent(msg: Record<string, unknown>): void {
    if (this.closed || !this.agent.isOpen) return;
    // Drop the undefined halves of a payload (an answer has a result or an error).
    for (const k of Object.keys(msg)) if (msg[k] === undefined) delete msg[k];
    this.agent.send(JSON.stringify(msg));
  }
}
