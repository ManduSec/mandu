/**
 * host-check — the Rules page's "Check a host" box under *Who may get your
 * secrets* (dashboard.md §4.25aa *Check a host*): the arbiter's read-only
 * `whyHost` answer (`mandu why <host>`, launcher/src/why.ts) in the page's
 * plain sentences. Mandu-new (no reference origin).
 *
 * Pure. Two halves:
 *   - `checkedHost`: the host a person typed, trimmed and lowercased, a
 *     pasted `https://`, port and path stripped, or the words of a refusal;
 *   - `hostCheckWords`: the answer as sentences, every name as code.
 *
 * Never a value. The answer carries paths, names, hosts and decisions; its
 * earlier answers and the sends still waiting (`verdicts`) name each send
 * by its `$MDU:` placeholder, and those are COUNTED here and dropped: no
 * placeholder reaches the page.
 * Display only: nothing here decides a send, and the box changes no rule.
 */

import type { HomeTextPart } from "./ask-words.js";
import { tildePath } from "./rule-words.js";

/** The arbiter's `whyHost` answer (the fields this box reads;
 *  arbiter/ipc/protocol.ts `WhyHostOpResult`). */
export interface WhyHostWire {
  host: string;
  axis: boolean;
  bound: Array<{ path: string; level: string; binding: string[]; source: "label" | "registry" }>;
  release: { bound: HostDecided | null; unbound: HostDecided | null };
  destinations: Array<{ host: string; port: number | "*"; proto: string; connect: string; reason?: string }>;
  verdicts: Array<{ symbol: string; status: string; scope: string }>;
  pending?: unknown[];
  issuer?: { id: string; name: string; shapes: string[]; on: boolean };
}

/** One probe of the egress gate: its decision and the stage that decided. */
export interface HostDecided {
  decision: { allow: boolean; requiresApproval?: boolean };
  stage: string;
}

/** A link in a line: Approvals, found by `q` (Answered earlier's search,
 *  §4.25 *Finding an answer*) when given. */
export interface HostCheckLink {
  kind: "link";
  text: string;
  to: "approvals";
  q?: string;
}

export type HostCheckPart = HomeTextPart | HostCheckLink;

export interface HostCheckLine {
  /** What the line says (the page's hook and the tests'). */
  kind: "off" | "bound" | "none" | "other" | "issuer" | "connect" | "answered" | "waiting" | "pending";
  /** The sentence: `parts` joined. */
  text: string;
  parts: HostCheckPart[];
  /** A `bound` line: each secret its code parts name, in their order, with
   *  the rule's own path (no `~`, no ": KEY") the page opens under Your
   *  rules when that row is drawn; null for a secret with no rule path. */
  files?: Array<{ name: string; rule: string | null }>;
}

export interface HostCheckVM {
  /** The host as asked. */
  host: string;
  lines: HostCheckLine[];
}

/** The longest host name DNS allows. */
export const HOST_MAX = 253;

/** The words of a host the box refuses. */
export const HOST_REFUSED = "Type a host name, like api.example.com: no https://, no path.";

const LABEL = "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?";
const HOST_RE = new RegExp(`^${LABEL}(?:\\.${LABEL})*$`);

/** The host in what a person typed or pasted: trimmed and lowercased, a
 *  scheme (`https://`), a port and a path, query or fragment stripped, and
 *  a trailing dot; or `{ error }` with words for anything else (empty, a
 *  space, a user name, an address in brackets, too long). */
export function checkedHost(raw: unknown): { host: string } | { error: string } {
  let s = (typeof raw === "string" ? raw : "").trim().toLowerCase();
  if (s === "") return { error: "Type a host name, like api.example.com." };
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  s = s.replace(/[/?#].*$/, "").replace(/:\d{1,5}$/, "").replace(/\.$/, "");
  if (s.length > HOST_MAX || !HOST_RE.test(s)) return { error: HOST_REFUSED };
  return { host: s };
}

const text = (t: string): HomeTextPart => ({ kind: "text", text: t });
const code = (t: string): HomeTextPart => ({ kind: "code", text: t });

function line(kind: HostCheckLine["kind"], parts: HostCheckPart[], files?: HostCheckLine["files"]): HostCheckLine {
  return { kind, text: parts.map((p) => p.text).join(""), parts, ...(files ? { files } : {}) };
}

/** `names` as code parts between commas. */
function listed(names: string[]): HostCheckPart[] {
  return names.flatMap((n, i) => (i ? [text(", "), code(n)] : [code(n)]));
}

/** The secrets bound there, as the page names them: a file `~/…`, a value
 *  of a file bound on its own `~/…: KEY` (a `values:` binding, which the
 *  arbiter sends as `KEY: host`), a registered variable by its name. Each
 *  name once. */
function boundNames(bound: WhyHostWire["bound"], home: string): Array<{ name: string; rule: string | null }> {
  const out: Array<{ name: string; rule: string | null }> = [];
  const add = (name: string, rule: string | null) => { if (!out.some((o) => o.name === name)) out.push({ name, rule }); };
  for (const b of bound) {
    if (typeof b.path !== "string" || b.path === "") continue;
    if (b.path.startsWith("env:")) { add(b.path.slice(4), null); continue; }
    const shown = tildePath(b.path, home);
    const keys = (b.binding ?? []).map((x) => /^([^\s:]+): /.exec(x)?.[1]).filter((k): k is string => !!k);
    if (b.source === "label" && keys.length) for (const k of [...new Set(keys)]) add(`${shown}: ${k}`, b.path);
    else add(shown, b.path);
  }
  return out;
}

/** What the gate does with a secret bound nowhere near this host. */
function otherWords(d: HostDecided | null): string {
  if (!d) return "Mandu could not work out what happens to any other secret sent there.";
  const by = d.stage === "verdict" ? ", as an earlier answer of yours says"
    : d.stage === "user-rule" ? ", as a rule of yours says"
    : "";
  if (d.decision.allow) return `Any other secret sent there: it goes out${by}.`;
  if (d.decision.requiresApproval) return `Any other secret sent there: Mandu asks you first${by}.`;
  return `Any other secret sent there: Mandu blocks it${by}.`;
}

/** A `connect: allow` row of `destinations:` in words. */
function connectLine(d: WhyHostWire["destinations"][number]): HostCheckLine {
  const where = d.port === "*" ? "on any port" : `on port ${d.port}`;
  const udp = d.proto === "udp" ? " over UDP" : "";
  if (d.host === "*") return line("connect", [text(`Your agent's programs may connect to every host ${where}${udp} (your rule).`)]);
  return line("connect", [text(`Your agent's programs may connect to it ${where}${udp} (your rule).`)]);
}

const count = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** The answer for one host in sentences. `home`: the dashboard's home, so
 *  paths read `~/…`. */
export function hostCheckWords(a: WhyHostWire, home: string): HostCheckVM {
  const lines: HostCheckLine[] = [];
  const connects = (a.destinations ?? []).filter((d) => d.connect === "allow").map(connectLine);
  if (!a.axis) {
    lines.push(line("off", [text("Protection is off: nothing is held back from any host.")]));
    return { host: a.host, lines: [...lines, ...connects] };
  }
  const names = boundNames(a.bound ?? [], home);
  if (names.length) {
    lines.push(line("bound", [
      text(`${names.length} of your secrets may be sent there: `),
      ...listed(names.map((n) => n.name)),
      text("."),
    ], names));
  } else lines.push(line("none", [text("None of your secrets may be sent there.")]));
  lines.push(line("other", [text(otherWords(a.release?.unbound ?? null))]));
  if (a.issuer) {
    const who = a.issuer.name;
    lines.push(line("issuer", [text(a.issuer.on
      ? `This is ${who}'s API host: a ${who} key goes here without asking.`
      : `This is ${who}'s API host: a ${who} key sent here asks you first.`)]));
  }
  lines.push(...connects);
  // The earlier answers, counted: their placeholders stay here.
  const answered = (a.verdicts ?? []).filter((v) => v.status !== "pending").length;
  if (answered) {
    lines.push(line("answered", [
      text(`You answered ${count(answered, "earlier send", "earlier sends")} to this host. `),
      { kind: "link", text: "Find them in Approvals", to: "approvals", q: a.host },
      text("."),
    ]));
  }
  // The sends waiting now, counted the same way; a prompt hold is not a
  // send (the arbiter's own `pendingAsks` leaves it out too).
  const waiting = (a.verdicts ?? []).filter((v) => v.status === "pending" && !String(v.symbol).startsWith("prompt:")).length;
  if (waiting) {
    lines.push(line("waiting", [
      text(`${count(waiting, "send", "sends")} to this host ${waiting === 1 ? "waits" : "wait"} for your answer in `),
      { kind: "link", text: "Approvals", to: "approvals" },
      text("."),
    ]));
  }
  const pending = (a.pending ?? []).length;
  if (pending) {
    lines.push(line("pending", [
      text(pending === 1 ? "A rule change waiting in " : `${pending} rule changes waiting in `),
      { kind: "link", text: "Approvals", to: "approvals" },
      text(" would change this."),
    ]));
  }
  return { host: a.host, lines };
}
