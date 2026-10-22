// scripts/agents/agent-registry.mjs — THE list of the agents Mandu supports
// and its test tooling drives (docs/design/agents/supported-agents.md §5.7).
//
// One row per agent LINE: an agent CLI (`claude`, `codex`, …), or a later
// generation of one that installs and runs as its own line (`opencode2`, the
// `opencode` agent's second generation). Every list of agents in the suite
// manifests, the suite runner, the test harness, the dashboards, the launcher
// and the arbiter is this table or a named filter over it, never a copy; tests/stack/agent-registry.test.ts
// fails on a hand-copied list in the public tree, and the drill suite holds its
// own tree to the same rule.
//
// Adding an agent starts here: a row, then agent-copies.mjs `generate`; the
// type checker then names every per-agent table (a `Record<Agent, …>`) that
// lacks the new agent, and the registry tests name the plain-JS and HTML ones.
// The launcher's copy makes a row a launch target (`--target <id>`), so a row
// lands with the launcher's support for its agent, never before it.
//
//   node scripts/agents/agent-copies.mjs generate   write the typed copies
//   node scripts/agents/agent-copies.mjs check      exit 1 when a copy is stale
//
// The copies (agent-copies.mjs writes them): this module's declarations
// (agent-registry.d.mts, which gives the TypeScript importers literal types)
// and the dashboard's, the launcher's and the arbiter's (each ships standalone
// and imports nothing outside its package: on-disk-layout.md §5's rule for
// mandu-paths).
//
// A second table, SCAN_ONLY_AGENTS, names the agents only the past-sessions
// scan knows (Mandu does not run them; supported-agents.md §5.7).
//
// Data only: no imports, no I/O (the drill catalog, which is data, imports it).

// ── the table ─────────────────────────────────────────────────────────────────

/**
 * Each row:
 *   id          the line's id: its `needs` name (the CLI), its suite-entry and
 *               `--agents` name;
 *   agent       the agent it is a line of (its own id unless a generation);
 *   name        the product name, as the tested-version table writes it;
 *   generation  a later generation's major version (absent: the agent's first line);
 *   wire        the model API it speaks to Mandu's model proxy in the test
 *               harnesses: `anthropic` (the anthropic-proxy) or `openai`;
 *   credential  what its live runs sign in with: `subscription` (its own
 *               subscription sign-in) or `api-key` (the Anthropic API key:
 *               Anthropic's subscription works only inside Claude Code);
 *   signIn      the `needs` name of its subscription sign-in (subscription only);
 *   cache       its CLI is pinned in the hand-run agent cache (the others come
 *               from PATH);
 *   pin         its version's key in scripts/ci/pins.env;
 *   npm         the npm package its CLI installs from (absent: not on npm;
 *               Goose ships as a release binary).
 */
export const AGENT_LINES = Object.freeze([
  row({ id: "claude", name: "Claude Code", wire: "anthropic", credential: "subscription", signIn: "claude-login", cache: false, pin: "CLAUDE_CODE_VERSION", npm: "@anthropic-ai/claude-code" }),
  row({ id: "codex", name: "Codex", wire: "openai", credential: "subscription", signIn: "chatgpt-login", cache: false, pin: "CODEX_VERSION", npm: "@openai/codex" }),
  row({ id: "openclaw", name: "OpenClaw", wire: "anthropic", credential: "api-key", cache: true, pin: "OPENCLAW_VERSION", npm: "openclaw" }),
  row({ id: "opencode", name: "OpenCode", wire: "anthropic", credential: "api-key", cache: true, pin: "OPENCODE_VERSION", npm: "opencode-ai" }),
  row({ id: "opencode2", agent: "opencode", generation: 2, name: "OpenCode 2", wire: "anthropic", credential: "api-key", cache: true, pin: "OPENCODE2_VERSION", npm: "@opencode/cli" }),
  row({ id: "goose", name: "Goose", wire: "anthropic", credential: "api-key", cache: true, pin: "GOOSE_VERSION" }),
]);

function row(r) {
  return Object.freeze({ ...r, agent: r.agent ?? r.id });
}

// ── the names and the named filters ──────────────────────────────────────────

/** Every line, in table order. */
export const LINES = Object.freeze(AGENT_LINES.map((l) => l.id));
/** The agents: each agent's first line (a generation is not another agent). */
export const AGENTS = Object.freeze(AGENT_LINES.filter((l) => l.agent === l.id).map((l) => l.id));
/** Each agent's product name. */
export const AGENT_NAMES = Object.freeze(Object.fromEntries(AGENT_LINES.filter((l) => l.agent === l.id).map((l) => [l.id, l.name])));
/** Each line's product name (a generation's carries its major: `OpenCode 2`). */
export const LINE_NAMES = Object.freeze(Object.fromEntries(AGENT_LINES.map((l) => [l.id, l.name])));
/** Each line's key in scripts/ci/pins.env. */
export const PIN_KEYS = Object.freeze(Object.fromEntries(AGENT_LINES.map((l) => [l.id, l.pin])));
/** The agents whose live runs take the Anthropic API key (no subscription path). */
export const API_KEY_AGENTS = Object.freeze(AGENTS.filter((a) => lineOf(a).credential === "api-key"));
/** The lines whose CLIs the hand-run agent cache pins. */
export const CACHED_LINES = Object.freeze(AGENT_LINES.filter((l) => l.cache).map((l) => l.id));
/** The agents, and the lines, that speak the Anthropic Messages API to the anthropic-proxy. */
export const ANTHROPIC_WIRE_AGENTS = Object.freeze(AGENTS.filter((a) => lineOf(a).wire === "anthropic"));
export const ANTHROPIC_WIRE_LINES = Object.freeze(AGENT_LINES.filter((l) => l.wire === "anthropic").map((l) => l.id));
/** The agents whose CLI installs from npm (the fresh-agents matrix suite installs
 *  these, os-test-matrix.md §10.14; Goose is a release binary). */
export const NPM_AGENTS = Object.freeze(AGENTS.filter((a) => lineOf(a).npm !== undefined));
/** The sign-in `needs` names, each with the agent it signs in. */
export const SIGN_IN_AGENTS = Object.freeze(Object.fromEntries(AGENT_LINES.filter((l) => l.signIn).map((l) => [l.signIn, l.agent])));

/** The row of a line, or undefined. */
export function lineOf(id) {
  return AGENT_LINES.find((l) => l.id === id);
}
/** The agent a line is a line of (a known agent's id answers itself; an unknown id too). */
export function agentOfLine(id) {
  return lineOf(id)?.agent ?? id;
}
export const isAgent = (s) => AGENTS.includes(s);
export const isLine = (s) => LINES.includes(s);

// ── the agents only the past-sessions scan knows ─────────────────────────────

/**
 * Agents people run without Mandu, which Mandu does not run (no launch, no
 * suite, no pin), whose local session stores `mandu scan` reads or counts
 * (docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md
 * §4, phase 3). Not lines. Each row:
 *   id    the scan's id for it (its answer's `sessions` and `agents`);
 *   name  the product name, as the report writes it;
 *   read  true: the scan reads its sessions; false: it only counts them, as
 *         its store's format is not one a reader can rely on (plan 17 §4).
 * When Mandu comes to run one, its row moves to AGENT_LINES.
 */
export const SCAN_ONLY_AGENTS = Object.freeze([
  Object.freeze({ id: "gemini", name: "Gemini CLI", read: true }),
  Object.freeze({ id: "copilot", name: "Copilot CLI", read: true }),
  Object.freeze({ id: "cursor", name: "Cursor", read: false }),
]);
/** The scan-only agents' ids, in table order. */
export const SCAN_ONLY_IDS = Object.freeze(SCAN_ONLY_AGENTS.map((a) => a.id));
/** Each scan-only agent's product name. */
export const SCAN_ONLY_NAMES = Object.freeze(Object.fromEntries(SCAN_ONLY_AGENTS.map((a) => [a.id, a.name])));
/** The scan-only agents whose sessions the scan reads (the others it counts). */
export const SCAN_READ_IDS = Object.freeze(SCAN_ONLY_AGENTS.filter((a) => a.read).map((a) => a.id));

/** What is wrong with the table, as messages (none: sound). */
export function tableProblems(lines = AGENT_LINES) {
  const out = [];
  const ids = new Set();
  for (const l of lines) {
    if (!/^[a-z][a-z0-9]*$/.test(l.id)) out.push(`${l.id}: an id is lower-case letters and digits`);
    if (ids.has(l.id)) out.push(`${l.id}: listed twice`);
    ids.add(l.id);
    const first = lines.find((x) => x.id === l.agent);
    if (!first || first.agent !== first.id) out.push(`${l.id}: its agent ${l.agent} is not a first line`);
    if ((l.agent === l.id) !== (l.generation === undefined)) out.push(`${l.id}: a generation, and only a generation, is a line of another agent`);
    if (!l.name) out.push(`${l.id}: no name`);
    if (!["anthropic", "openai"].includes(l.wire)) out.push(`${l.id}: wire ${l.wire}`);
    if (!["subscription", "api-key"].includes(l.credential)) out.push(`${l.id}: credential ${l.credential}`);
    if ((l.credential === "subscription") !== (typeof l.signIn === "string")) out.push(`${l.id}: a subscription line, and only one, names its sign-in`);
    if (typeof l.cache !== "boolean") out.push(`${l.id}: cache is true or false`);
    if (!/^[A-Z0-9_]+_VERSION$/.test(l.pin ?? "")) out.push(`${l.id}: pin ${l.pin}`);
    if (l.npm !== undefined && !/^(?:@[a-z0-9-]+\/)?[a-z0-9][a-z0-9._-]*$/.test(l.npm)) out.push(`${l.id}: npm ${l.npm}`);
  }
  for (const a of SCAN_ONLY_AGENTS) {
    if (!/^[a-z][a-z0-9]*$/.test(a.id)) out.push(`${a.id}: an id is lower-case letters and digits`);
    if (ids.has(a.id)) out.push(`${a.id}: a scan-only agent is no line (and is listed once)`);
    ids.add(a.id);
    if (!a.name) out.push(`${a.id}: no name`);
    if (typeof a.read !== "boolean") out.push(`${a.id}: read is true or false`);
  }
  return out;
}
