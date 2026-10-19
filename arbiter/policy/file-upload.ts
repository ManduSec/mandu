/**
 * file-upload — may a tool send a LOCAL FILE's bytes off the machine?
 * (supported-agents.md §2, "Claude Code 2.1.292"; confidentiality.md §7,
 * "A tool that uploads a local file").
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code; the reference
 * implementation had no upload tool. Shape mirrors decideFsPath
 * (fs-outbound.ts): a PURE function over the request and the facts the
 * server gathered, unit-tested as an oracle; the stateful approval queue
 * wraps it in ipc/server.ts (`fileUploadDecision`), never here.
 *
 * WHY A GATE OF ITS OWN. Every other way a file's bytes leave goes through
 * the model context first (the proxy symbolizes a `tool_result`) or through
 * a process Mandu confines (the secret twins, the egress proxy). Claude
 * Code's `DesignSync{method: "write_files", files[].localPath}` reads the
 * file in the agent's own process and uploads it to claude.ai: the bytes
 * never enter the model context, so no symbol is ever minted for them, and
 * the only on-wire trace is the PATH the model wrote. So the path is judged:
 * what the file is (its label, its registration) and what it holds (the
 * registered secret values in its bytes).
 *
 * Rule order (first match decides):
 *   0. THE UNMAPPED FORM only (`unmapped: true`, 2026-10-17; guarantees.md
 *      §3): the proxy asks about every local path in the input of a tool its
 *      gate tables do not name (an MCP server's tool, a tool a new agent
 *      release added), which may upload what it names. A tool the session
 *      maps (its spec, harness or gate surface, Mandu's own: `facts.mapping`)
 *      is judged by its own legs → allow, nothing read; a tool of an MCP
 *      server the launcher registered as a local process, in a session the
 *      file guard confines (`facts.confinedServer`), is a program the guard
 *      and the egress proxy confine like any the agent runs → allow;
 *   1. an empty or relative path → deny + approval (fail-closed: the proxy
 *      resolves every path it gates; a relative one here is out of contract);
 *   2. asked on the data socket → deny (the agent's tools reach that socket,
 *      and a claim there must never make the arbiter read a file);
 *   3. a built-in sensitive path (fs-outbound.ts SENSITIVE_PATHS: keys,
 *      credential stores, agent configs) → deny + approval, axis or not, as
 *      for a read of it; a file of a process or of the kernel (`/proc`,
 *      `/sys`, `/dev/fd`, `/dev/std*`) too: the arbiter would read its OWN
 *      process's file, not the tool's (`fs:upload-process-file`);
 *   4. the confidentiality axis OFF → allow (nothing else is labelled);
 *   4a. the unmapped form: nothing at the path, or no stored bytes (a
 *      device, a FIFO, a socket) → allow (`fs:upload-no-file`): the input
 *      merely looks like a path (a remote API's `/v1/items`), or names a
 *      file that does not exist when the call is relayed (the window, below);
 *   5. a label above `public` (a human label, the catalog, a derived label,
 *      a registered secret file) whose bindings do not name EVERY destination
 *      → deny + approval;
 *   5a. the unmapped form: a folder → allow (`fs:upload-folder`), judged by
 *      its own label (5) and the sensitive paths (3) only, never by the files
 *      in it (a tool that takes a folder mostly lists or searches it; the
 *      guard twins the secret files in it under `confined`);
 *   6. bytes the server could not read whole (missing, not a regular file,
 *      over the size bound FILE_UPLOAD_MAX_BYTES, 256 MiB, a scan past its
 *      deadline, a read error) → deny + approval (fail-closed: unread bytes
 *      are unchecked bytes);
 *   7. bytes holding a registered secret value whose row is not bound to
 *      every destination → deny + approval;
 *   8. otherwise allow (bound, when a label or value was secret but bound).
 *
 * DESTINATIONS (2026-10-17). A binding releases a secret only to the hosts
 * it names, and an upload tool may reach more than one: Claude Code's
 * DesignSync posts to the OAuth API host (`api.anthropic.com/v1/design/mcp`)
 * and its Artifact tools' file bytes go to that host's upload URLs while the
 * tools present as claude.ai (read off the 2.1.302 binary:
 * arbiter/test/fixtures/claude-upload-hosts-2026-10-17.json). So a request
 * names every host (`destination` and `destinations`), and a label or value
 * counts as bound only when its bindings name EACH of them. The unmapped
 * form names none: nothing it uploads is ever bound (its host is unknown);
 * neither do OpenClaw's chat attachments (`message`) and browser uploads,
 * whose channel or page the proxy cannot name (tool-gate-surface.ts
 * UploadKind).
 *
 * TO A MODEL (`toModel`, 2026-10-17). OpenClaw's `view_image`, `image`,
 * `pdf` and media generators send a local file's bytes to a model (the
 * session's own, or one OpenClaw picks), not to a network service. A label
 * or value at `any-model` admits every model, so it counts as bound there
 * (rules 5 and 7); `local-model` and `no-model` do not, since the model the
 * bytes reach is not known to be local, and are held as above.
 *
 * PATH FIRST, BYTES STREAMED (2026-10-17). Rules 0–5a decide on the path
 * and its labels alone (`decideFileUploadByPath`); the server opens the file
 * only when they do not, and then reads it in chunks (upload-scan.ts), never
 * whole: a large image, video or PDF with no registered value in it goes,
 * where it was held at the old 8 MiB read limit.
 *
 * THE WINDOW. The gate reads the file when the call is relayed, not when
 * the tool reads it. The proxy refuses an upload that follows, in the same
 * model turn, a call that may write files (upload-gate.ts); the rest is the
 * confinement's (guarantees.md §3).
 *
 * Every spelling the server resolved (the path as written and, through a
 * symlink, its real path) is judged; the strictest answer wins.
 */

import { homedir } from "node:os";
import path from "node:path";

import { isSecret, type ConfidentialityLevel } from "../symbol-table/confidentiality.js";
import { SENSITIVE_PATHS, normalizeFsPath, type FsPathDecision } from "./fs-outbound.js";
import { destinationMatchesBindings } from "./policy-interface.js";
import { ruleRef } from "./rule-ref.js";

/** May tool `tool` send the bytes of the local file `path` to `destination`? */
export interface FileUploadDecisionRequest {
  /** The tool that uploads (e.g. "DesignSync"); recorded in the queue key. */
  tool: string;
  /** The ABSOLUTE HumanView path the tool reads. */
  path: string;
  /** The host the bytes go to (e.g. "claude.ai"); "" when it is not known
   *  (the unmapped form), so no binding releases anything. */
  destination: string;
  /** More hosts the same bytes may reach (a tool that presents as one
   *  service and sends to another's host): a binding must name each. */
  destinations?: readonly string[];
  /** The bytes go to a MODEL (module header, "TO A MODEL"): `any-model`
   *  admits it, whatever the bindings. */
  toModel?: boolean;
  /** The unmapped form (rule 0): a local path in the input of a tool the
   *  proxy's gate tables do not name. The server answers rule 0 from the
   *  session's mapping; nothing at the path, or a folder, is then no upload. */
  unmapped?: boolean;
  /** The approval row's session; in the unmapped form also the session whose
   *  mapping and guard rule 0 reads (asked on the human plane only: rule 2
   *  answers first on the data socket). */
  sessionKey?: string;
}

/** The same shape as the sensitive-path gate's verdict (an approval row id
 *  stamped by the server wrap when it queued one). */
export type FileUploadDecision = FsPathDecision;

/** One label the server found for a spelling of the path. */
export interface UploadLabelFact {
  path: string;
  level: ConfidentialityLevel;
  bindings: readonly string[];
  /** What decided it (`label:<via>`, a catalog rule, `registry`). */
  rule: string | null;
}

/** What the server read of the file's bytes. */
export type UploadContentFact =
  | { kind: "read"; hits: ReadonlyArray<{ level: ConfidentialityLevel; bindings: readonly string[] }> }
  | { kind: "unreadable"; why: string };

/** What the canonical path names, as the server found it (the unmapped
 *  form's rules 4a and 5a; the mapped form reads only `content`). */
export type UploadPresence = "file" | "missing" | "directory" | "special";

export interface FileUploadFacts {
  /** False: asked on the data socket (rule 2). */
  attested: boolean;
  /** The unmapped form only (rule 0): the session's mapping of the tool
   *  (mapped-tools.ts ToolMapping), null when it has none. */
  mapping?: string | null;
  /** The unmapped form only (rule 0): a registered local MCP server's tool,
   *  in a session the file guard confines. */
  confinedServer?: boolean;
  /** What the canonical path names (rules 4a, 5a). Absent: read as a file
   *  (the content fact decides). */
  presence?: UploadPresence;
  /** The confidentiality axis (rule 4). */
  axis: boolean;
  /** Every spelling judged: the canonical path and its real path. */
  paths: readonly string[];
  /** Labels of those spellings (rule 5); empty when the axis is off. */
  labels: readonly UploadLabelFact[];
  /** The bytes (rules 6–7); null when the axis is off or the ask is unattested. */
  content: UploadContentFact | null;
  /** Home for the `~/…` sensitive entries (tests). */
  home?: string;
}

function underRoot(p: string, root: string): boolean {
  return p === root || p.startsWith(root + "/");
}

/** Rule 3's second half: files of a process or of the kernel. The arbiter
 *  would read its own (`/proc/self`, its descriptors), never the tool's. */
const PROCESS_FILE_ROOTS: readonly string[] = ["/proc", "/sys", "/dev/fd"];
const PROCESS_FILES: readonly string[] = ["/dev/stdin", "/dev/stdout", "/dev/stderr"];

/** Mappings that keep their own legs (rule 0): every one but a policy.yaml
 *  `mapped_tools:` entry, which lifts the result mask and no input rule
 *  (mapped-tools.ts), and an MCP server's registration (`mcp-config`),
 *  which rule 0 reads together with the guard (`confinedServer`). */
const OWN_LEGS: ReadonlySet<string> = new Set(["own", "spec", "harness", "surface", "builtin"]);

/** Does rule 0 answer without reading the file? (The server asks it before
 *  it gathers the facts, so an exempt tool's path is never opened.) Pure. */
export function isUploadExempt(f: Pick<FileUploadFacts, "mapping" | "confinedServer">): boolean {
  return (typeof f.mapping === "string" && OWN_LEGS.has(f.mapping)) || f.confinedServer === true;
}

/** The pure upload gate. See the module header for the rule order. */
export function decideFileUpload(req: FileUploadDecisionRequest, facts: FileUploadFacts): FileUploadDecision {
  const byPath = judgeByPath(req, facts);
  return "decision" in byPath ? byPath.decision : judgeBytes(facts, byPath);
}

/**
 * Rules 0–5a alone, the path phase (no byte of the file read; `content` is
 * not consulted): the verdict when they decide, null when the bytes must
 * (rules 6–8). The server asks it before it opens the file, so a held
 * secret path, a sensitive path, a folder or nothing-there is never read
 * (STREAMED, confidentiality.md §7). Pure.
 */
export function decideFileUploadByPath(req: FileUploadDecisionRequest, facts: FileUploadFacts): FileUploadDecision | null {
  const byPath = judgeByPath(req, facts);
  return "decision" in byPath ? byPath.decision : null;
}

/** What the path phase hands the bytes phase. */
interface PathPhase {
  shown: string;
  tool: string;
  destWords: string;
  /** A secret label was found bound to every destination. */
  bound: boolean;
  boundEverywhere: (level: ConfidentialityLevel, bindings: readonly string[]) => boolean;
  emptyBoundWords: boolean;
}

function judgeByPath(req: FileUploadDecisionRequest, facts: FileUploadFacts): { decision: FileUploadDecision } | PathPhase {
  const decided = (decision: FileUploadDecision): { decision: FileUploadDecision } => ({ decision });
  const home = facts.home ?? homedir();
  const unmapped = req.unmapped === true;
  if (unmapped && typeof facts.mapping === "string" && OWN_LEGS.has(facts.mapping)) {
    return decided({ allow: true, reason: `'${req.tool}' is a tool Mandu maps (${facts.mapping}): its own checks judge its paths`, ruleRef: ruleRef("fs:upload-mapped-tool") });
  }
  if (unmapped && facts.confinedServer === true) {
    return decided({ allow: true, reason: `'${req.tool}' runs in a local MCP server, a program the file guard confines like any the agent runs`, ruleRef: ruleRef("fs:upload-confined-server") });
  }
  const raw = typeof req.path === "string" ? req.path.trim() : "";
  if (raw === "" || !path.posix.isAbsolute(normalizeFsPath(raw, home))) {
    return decided({
      allow: false, requiresApproval: true,
      reason: "fail-closed: an upload names its file by an absolute path; this one could not be placed",
      ruleRef: ruleRef("fs:upload-invalid-path"),
    });
  }
  const shown = normalizeFsPath(raw, home);
  const dests = [req.destination, ...(Array.isArray(req.destinations) ? req.destinations : [])]
    .filter((d): d is string => typeof d === "string")
    .map((d) => d.trim())
    .filter((d, i, all) => d !== "" && all.indexOf(d) === i);
  const toModel = req.toModel === true;
  const destWords = dests.length > 0 ? dests.join(" and ") : toModel ? "a model Mandu cannot name" : "an unnamed destination";
  /** Bound only where the bindings name EVERY host the bytes may reach; to
   *  a model, also a level that admits every model (header, "TO A MODEL"). */
  const boundEverywhere = (level: ConfidentialityLevel, bindings: readonly string[]): boolean =>
    (toModel && level === "any-model") || (dests.length > 0 && dests.every((d) => destinationMatchesBindings(d, [...bindings])));
  if (!facts.attested) {
    return decided({
      allow: false, requiresApproval: false,
      reason: "fail-closed: an upload is checked only when the model proxy asks on the human plane; this ask came on the data socket",
      ruleRef: ruleRef("fs:upload-unattested"),
    });
  }
  const spellings = facts.paths.length > 0 ? facts.paths : [shown];
  for (const p of spellings) {
    const n = normalizeFsPath(p, home);
    for (const entry of SENSITIVE_PATHS) {
      if (underRoot(n, normalizeFsPath(entry, home))) {
        return decided({
          allow: false, requiresApproval: true,
          reason: `sensitive path (${entry}): upload of '${shown}' by '${req.tool}' to ${destWords} requires approval`,
          ruleRef: ruleRef("fs:sensitive-path"),
        });
      }
    }
    if (PROCESS_FILE_ROOTS.some((r) => underRoot(n, r)) || PROCESS_FILES.includes(n)) {
      return decided({
        allow: false, requiresApproval: true,
        reason: `'${shown}' is a file of a running process or of the kernel, which Mandu cannot read as '${req.tool}' would: upload to ${destWords} requires approval`,
        ruleRef: ruleRef("fs:upload-process-file"),
      });
    }
  }
  if (!facts.axis) {
    return decided({ allow: true, reason: "the confidentiality axis is off: no file is labelled", ruleRef: ruleRef("fs:upload-clean") });
  }
  if (unmapped && (facts.presence === "missing" || facts.presence === "special")) {
    return decided({
      allow: true,
      reason: facts.presence === "missing" ? `nothing is at '${shown}': no file to send` : `'${shown}' holds no stored bytes (a device, a pipe or a socket)`,
      ruleRef: ruleRef("fs:upload-no-file"),
    });
  }
  let bound = false;
  for (const l of facts.labels) {
    if (!isSecret(l.level)) continue;
    if (boundEverywhere(l.level, l.bindings)) { bound = true; continue; }
    return decided({
      allow: false, requiresApproval: true,
      reason: `'${shown}' is a secret file (${l.level}${l.rule ? `, ${l.rule}` : ""}) and no rule lets it go to ${destWords}: upload by '${req.tool}' requires approval`,
      ruleRef: ruleRef("fs:upload-secret-file"),
    });
  }
  if (unmapped && facts.presence === "directory") {
    return decided({ allow: true, reason: `'${shown}' is a folder with no secret label: the files in it are not looked into`, ruleRef: ruleRef("fs:upload-folder") });
  }
  return { shown, tool: req.tool, destWords, bound, boundEverywhere, emptyBoundWords: dests.length === 0 && toModel };
}

/** Rules 6–8, the bytes phase: what the server read of the file decides. */
function judgeBytes(facts: FileUploadFacts, at: PathPhase): FileUploadDecision {
  const { shown, tool, destWords, boundEverywhere } = at;
  let bound = at.bound;
  const content = facts.content;
  if (content === null || content.kind === "unreadable") {
    return {
      allow: false, requiresApproval: true,
      reason: `fail-closed: the bytes of '${shown}' could not be checked (${content === null ? "not read" : content.why}): upload by '${tool}' requires approval`,
      ruleRef: ruleRef("fs:upload-unreadable"),
    };
  }
  for (const h of content.hits) {
    if (!isSecret(h.level)) continue;
    if (boundEverywhere(h.level, h.bindings)) { bound = true; continue; }
    return {
      allow: false, requiresApproval: true,
      reason: `'${shown}' holds a registered secret value (${h.level}) that no rule lets go to ${destWords}: upload by '${tool}' requires approval`,
      ruleRef: ruleRef("fs:upload-secret-value"),
    };
  }
  return bound
    ? { allow: true, reason: at.emptyBoundWords ? `every secret in '${shown}' is at a level that admits any model` : `every secret in '${shown}' is bound to ${destWords}`, ruleRef: ruleRef("fs:upload-bound") }
    : { allow: true, reason: `'${shown}' has no secret label and holds no registered secret value`, ruleRef: ruleRef("fs:upload-clean") };
}
