// @ts-check
/**
 * summary — what a CI run of Mandu kept from the model and what it did with
 * each send, as the job summary (`$GITHUB_STEP_SUMMARY`) shows it (pure).
 *
 * NAMES AND HOSTS ONLY, NEVER A VALUE. The arbiter's event log carries the
 * original side of every masked span (event-model.ts `DualRepr.original`), so
 * this reader never copies free text out of an event. It takes a fixed set
 * of fields, and every string it keeps must match a shape that cannot hold a
 * value:
 *   - a placeholder name (`$MDU:nomodel_Env[833c].DEPLOY_TOKEN`), by
 *     SYMBOL_RE, rendered as the variable or key name it carries;
 *   - a host name, by HOST_RE;
 *   - the launch's own environment line (`mandu: environment: 2 secret
 *     variables masked (A, B)`), by ENV_LINE_RE, whose names are variable
 *     names;
 *   - a rule id (`egress:secret-unbound`), by RULE_RE;
 *   - from `mandu doctor --secrets --json` (names only by contract), the
 *     credential files' paths and levels and the masked variable names.
 * Anything else is dropped, not escaped.
 *
 * Design: docs/design/distribution/github-action.md §6.
 * Mandu-new (no reference origin).
 */

/** A placeholder: level, tool, short hash, an optional field path. */
export const SYMBOL_RE = /^\$MDU:([a-z]+)_([A-Za-z0-9_.-]{1,64})\[([0-9a-f]{2,32})\](?:\.([A-Za-z0-9_.*-]{1,128}))?$/;
/** A host name, with an optional port. */
export const HOST_RE = /^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\d{1,5})?$/;
/** The launch's env-mask line (launcher/src/secret-setup.ts applyEnvSecrets). */
export const ENV_LINE_RE = /^mandu: environment: \d+ secret variables? masked \(([A-Za-z0-9_, ]+)\)$/;
/** A rule id (arbiter/policy/rule-ref.ts). */
export const RULE_RE = /^[a-z][a-z0-9-]*(:[a-z0-9][a-z0-9:._-]*)?$/;
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const LEVELS = new Set(["public", "any-model", "local-model", "no-model"]);
const POSTURES = new Set(["confined", "gated", "read-blocked", "off"]);
const MODES = new Set(["secrets", "off", "injection", "full"]);

/**
 * What a placeholder stands for, in words, or null when it is not one.
 * @param {unknown} s
 */
export function symbolLabel(s) {
  if (typeof s !== "string") return null;
  const m = SYMBOL_RE.exec(s);
  if (!m) return null;
  const [, , tool, , field] = m;
  if (tool === "Env") return field ? { name: field.split(".")[0], kind: "environment variable" } : { name: "an environment variable", kind: "environment variable" };
  if (field) return { name: field, kind: "a value in a secret file" };
  return { name: tool === "Read" ? "a secret file" : `${tool} output`, kind: "a whole file or output" };
}

/**
 * @typedef {object} RunReport
 * @property {string | null} agent         "Claude Code 2.1.295"
 * @property {string | null} mode
 * @property {string | null} posture
 * @property {number | null} exitCode
 * @property {string[]} envMasked          variable names
 * @property {Array<{ path: string, level: string }>} files
 * @property {number} maskedResults        tool results the model got masked
 * @property {Array<{ host: string, names: string[], rule: string | null, count: number }>} blocked
 * @property {Array<{ host: string, names: string[], count: number }>} sent
 */

/** @param {Map<string, { names: Set<string>, rule: string | null, count: number }>} m */
function hostRows(m) {
  return [...m].sort(([a], [b]) => a.localeCompare(b)).map(([host, r]) => ({ host, names: [...r.names].sort(), rule: r.rule, count: r.count }));
}

/** @param {unknown} xs */
function symbolNames(xs) {
  if (!Array.isArray(xs)) return [];
  return xs.map((x) => symbolLabel(x)?.name).filter((n) => typeof n === "string");
}

/**
 * Fold a run's events (every session file under the run's event dir) and the
 * doctor's report into one RunReport.
 * @param {Array<Record<string, any>>} events
 * @param {Record<string, any> | null} doctor  `mandu doctor --secrets --json`
 * @param {{ home?: string, workspace?: string }} [where]
 * @returns {RunReport}
 */
export function collectReport(events, doctor, where = {}) {
  /** @type {RunReport} */
  const r = { agent: null, mode: null, posture: null, exitCode: null, envMasked: [], files: [], maskedResults: 0, blocked: [], sent: [] };
  const env = new Set();
  /** @type {Map<string, { names: Set<string>, rule: string | null, count: number }>} */
  const blocked = new Map();
  /** @type {Map<string, { names: Set<string>, rule: string | null, count: number }>} */
  const sent = new Map();
  const add = (/** @type {typeof blocked} */ m, /** @type {unknown} */ host, /** @type {string[]} */ names, /** @type {string | null} */ rule) => {
    if (typeof host !== "string" || !HOST_RE.test(host)) return;
    const row = m.get(host) ?? { names: new Set(), rule: null, count: 0 };
    for (const n of names) row.names.add(n);
    if (rule && !row.rule) row.rule = rule;
    row.count++;
    m.set(host, row);
  };
  let envFromLaunch = false;
  // The model proxy masks a tool result again on every later turn that
  // carries it: count each call once.
  const maskedCalls = new Set();
  for (const e of events) {
    if (!e || typeof e !== "object") continue;
    if (e.kind === "launch_posture" && e.emitter === "launcher") {
      const av = e.agentVersion;
      if (av && typeof av.name === "string" && /^[A-Za-z ]{1,32}$/.test(av.name)) {
        r.agent = typeof av.version === "string" && /^[0-9][0-9A-Za-z.+-]{0,31}$/.test(av.version) ? `${av.name} ${av.version}` : av.name;
      }
      if (MODES.has(e.protection?.mode)) r.mode = e.protection.mode;
      if (POSTURES.has(e.secrets?.posture)) r.posture = e.secrets.posture;
      for (const line of Array.isArray(e.notes) ? e.notes : []) {
        const m = typeof line === "string" ? ENV_LINE_RE.exec(line) : null;
        if (!m) continue;
        envFromLaunch = true;
        for (const n of m[1].split(/[, ]+/)) if (NAME_RE.test(n)) env.add(n);
      }
    } else if (e.kind === "session_exit" && e.emitter === "launcher") {
      if (Number.isInteger(e.code)) r.exitCode = e.code;
    } else if (e.kind === "net_action") {
      const rule = typeof e.policy?.ruleRef?.id === "string" && RULE_RE.test(e.policy.ruleRef.id) ? e.policy.ruleRef.id : null;
      if (e.action === "blocked") add(blocked, e.destination, symbolNames(e.withheld), rule);
      else if (e.action === "forwarded" && Array.isArray(e.resolved) && e.resolved.length > 0) add(sent, e.destination, symbolNames(e.resolved), null);
    } else if (e.kind === "symbolize" && e.view === "AgentView" && e.output?.differs === true) {
      maskedCalls.add(typeof e.callId === "string" ? `${e.sessionId}:${e.callId}` : `event:${maskedCalls.size}`);
    }
  }
  if (!envFromLaunch && Array.isArray(doctor?.env?.masked)) {
    for (const n of doctor.env.masked) if (typeof n === "string" && NAME_RE.test(n)) env.add(n);
  }
  r.maskedResults = maskedCalls.size;
  r.envMasked = [...env].sort();
  if (Array.isArray(doctor?.files)) {
    for (const f of doctor.files) {
      if (!f || typeof f.path !== "string" || /[\u0000-\u001f\u007f]/.test(f.path)) continue;
      r.files.push({ path: displayPath(f.path, where), level: LEVELS.has(f.level) ? f.level : "secret" });
    }
    r.files.sort((a, b) => a.path.localeCompare(b.path));
  }
  r.blocked = hostRows(blocked);
  r.sent = hostRows(sent).map(({ host, names, count }) => ({ host, names, count }));
  return r;
}

/** A path relative to the workspace (`./.env`) or the home (`~/.aws/credentials`). */
export function displayPath(p, where = {}) {
  const ws = where.workspace?.replace(/\/+$/, "");
  const home = where.home?.replace(/\/+$/, "");
  if (ws && p.startsWith(`${ws}/`)) return p.slice(ws.length + 1);
  if (home && p.startsWith(`${home}/`)) return `~/${p.slice(home.length + 1)}`;
  return p;
}

/** A code span that markdown and GitHub render literally. */
export function code(s) {
  return "`" + String(s).replace(/`/g, "'").replace(/\|/g, "\\|") + "`";
}

const LEVEL_WORDS = { "no-model": "no AI may read it", "local-model": "only your own AI", "any-model": "any AI, when it asks", public: "not secret", secret: "secret" };

/**
 * The job summary, in Markdown.
 * @param {RunReport} r
 * @param {{ failOnBlocked: boolean, policyFrom: string }} o
 */
export function renderSummary(r, o) {
  const out = [];
  out.push("## Mandu: what the AI did not see");
  out.push("");
  const facts = [
    r.agent ? `**${r.agent}**` : "the agent",
    `mode \`${r.mode ?? "unknown"}\``,
    `secrets ${r.posture ? `\`${r.posture}\`` : "posture unknown"}`,
    r.exitCode === null ? "the agent did not report an exit" : `exit ${r.exitCode}`,
    `policy: ${o.policyFrom}`,
  ];
  out.push(facts.join(" · "));
  out.push("");
  out.push("The model saw these as placeholders only. The job's log shows placeholders too: Mandu puts real values back only on the way to a host a rule binds them to.");
  out.push("");
  out.push("### Masked from the model");
  out.push("");
  if (r.envMasked.length === 0 && r.files.length === 0) {
    out.push("Nothing secret was found in this job's environment or files.");
  } else {
    out.push("| Secret | Where | Rule |");
    out.push("|---|---|---|");
    for (const n of r.envMasked) out.push(`| ${code(n)} | environment variable | sent only where a binding allows |`);
    for (const f of r.files) out.push(`| ${code(f.path)} | file | ${LEVEL_WORDS[/** @type {keyof typeof LEVEL_WORDS} */ (f.level)] ?? f.level} |`);
  }
  if (r.maskedResults > 0) {
    out.push("");
    out.push(`${r.maskedResults} tool result${r.maskedResults === 1 ? "" : "s"} reached the model with a secret replaced by its placeholder.`);
  }
  out.push("");
  out.push("### Sends");
  out.push("");
  if (r.blocked.length === 0 && r.sent.length === 0) {
    out.push("No request carried a secret.");
  } else {
    out.push("| Result | Host | Secrets | Requests |");
    out.push("|---|---|---|---|");
    for (const b of r.blocked) out.push(`| blocked | ${code(b.host)} | ${b.names.map(code).join(", ") || "a secret"} | ${b.count} |`);
    for (const s of r.sent) out.push(`| sent with the real value (bound) | ${code(s.host)} | ${s.names.map(code).join(", ")} | ${s.count} |`);
  }
  if (r.blocked.length > 0) {
    out.push("");
    out.push("A blocked request sent nothing. Nobody can approve one in CI, so it stays blocked; " +
      "if the host is right, bind the secret to it (the `bindings` input, or `bindings:` in the policy file) and run again." +
      (o.failOnBlocked ? " This step fails because of it (`fail-on-blocked`)." : ""));
  }
  out.push("");
  return out.join("\n");
}

/** The step's log lines and annotations for the blocked sends. */
export function blockedAnnotations(r) {
  return r.blocked.map((b) => `::error title=Mandu blocked a send::${b.names.join(", ") || "a secret"} to ${b.host} (${b.count} request${b.count === 1 ? "" : "s"}): no binding allows it, and nobody approves in CI`);
}
