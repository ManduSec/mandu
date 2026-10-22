#!/usr/bin/env node
// scripts/suites.mjs — read the suite manifest (tests/suites.mjs) from bash, CI and
// the runner (docs/design/testing/test-organization.md §5). Node builtins only.
//
//   node scripts/suites.mjs list [--kind a,b] [--frozen] [--platform linux|darwin] [--only ids] [--json | --ids]
//                                [--include-flaky] [--include-internet] [--needs-within offline|n,n]
//                                [--unsharded] [--public]
//        --frozen     the frozen (integrity) lane's entries too, whatever their kind
//        --unsharded  the entries as declared (a sharded entry stays one entry and keeps
//                     its `shards` array) instead of one entry per shard
//        --public     leave out private/suites.mjs (what the public snapshot has)
//        --native-bins  only the entries that run the kernel-feature bins
//                     (replay-drill, sandbox, or needs native-bins; usesNativeBins)
//   node scripts/suites.mjs packages [--kind a,b]   # dirs with a package.json to `npm ci`
//   node scripts/suites.mjs check [--json]          # the completeness check (exit 1 on an error),
//                                                   # a stale docs/testing/suites.md included
//   node scripts/suites.mjs doc [--check]           # write docs/testing/suites.md from the public
//                                                   # manifest; --check exits 1 when it is stale
//   node scripts/suites.mjs coverage [--json]       # the property x kind table of `proves`
//                                                   # (test-reorganization.md §5.2)
//
// Also imported: scripts/run-suites.mjs (selection, ordering) and
// scripts/test/suites-manifest.test.mjs (the check).

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { constants as osConstants } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { AGENTS as REGISTRY_AGENTS, AGENT_LINES, LINES, SIGN_IN_AGENTS, agentOfLine } from "./agents/agent-registry.mjs";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The kinds: what is real in a suite, which decides when it runs (test-reorganization.md §3). */
export const KINDS = ["unit", "component", "stack", "replay-drill", "sandbox", "live-drill", "env", "eval", "install"];
/** What every push runs; blocking (test-reorganization.md §3, §6.9). */
export const PER_PUSH_KINDS = ["unit", "component", "stack", "replay-drill", "sandbox"];
/** What the nightly runs, reported (continuous-integration.md §9.1); it also runs every flaky entry. */
export const NIGHTLY_KINDS = ["live-drill", "env", "eval"];
/** The per-push kinds that need nothing beyond node, cargo and base shell tools (OFFLINE_NEEDS). */
export const HOST_FREE_KINDS = ["unit", "component", "stack"];
/** The credential a nightly entry needs, which is its nightly lane (continuous-integration.md §9.8):
 *  `subscription` holds the Claude and ChatGPT sign-ins, `api-key` the vendor API keys. An
 *  entry that needs no login holds none, and the subscription lane runs it
 *  (test-reorganization.md §8 step 2): that guest has the network and the host's Ollama. */
export const CREDENTIALS = ["subscription", "api-key"];
/** Does a nightly run take this entry (so it must say which credential)? A
 *  `nightly` entry of a per-push kind runs there, with the flaky entries. */
export const nightlyRuns = (x) => !x.manual && x.idOnly !== true && !x.frozen && x.kind !== "install" &&
  (NIGHTLY_KINDS.includes(x.kind) || x.flaky != null || x.nightly != null);
/** Does the entry run without blocking: `flaky`, `reported` (a per-push entry
 *  whose red is reported, test-reorganization.md §6.9) or `nightly` (a
 *  per-push kind's entry the nightly runs instead)? run-suites leaves its red
 *  out of the run's result. */
export const nonBlocking = (x) => x.flaky != null || x.reported != null || x.nightly != null;
/** Does the entry run in the kernel lane (the per-push kernel guest)? */
export const needsKernel = (x) => (x.needs ?? []).includes("kernel");
/** The needs that are an API key: an entry with one is in the API lane. */
/** The browser agents a live drill can drive through the DevTools relay
 *  (`browserAgent`; docs/design/agents/devtools-relay.md): not registry
 *  agents, as they call their own model services. */
export const BROWSER_AGENTS = ["jev", "browser-use"];
export const API_KEY_NEEDS = ["anthropic-api-key", "openai-api-key", "typesafe-api-key", "openrouter-api-key"];
/** The needs that are a subscription sign-in (the agent registry rows' `signIn`): only the subscription lane holds them. */
export const SIGN_IN_NEEDS = Object.keys(SIGN_IN_AGENTS);
/** Does the entry need a login (a sign-in or an API key), so it must name its credential? */
export const needsLogin = (x) => (x.needs ?? []).some((n) => SIGN_IN_NEEDS.includes(n) || API_KEY_NEEDS.includes(n));
/** Is the entry in lane L's run: its credential, or none in the subscription lane. */
export const inLane = (x, lane) => (x.credential ?? "subscription") === lane;
/** The agents a run can be limited to (`--agents`; the agent registry,
 *  scripts/agents/agent-registry.mjs), and the needs that mean each: the
 *  agent's CLI (a generation's counts as its agent's), or its login (an entry
 *  that needs the Claude subscription login drives the claude CLI; the ChatGPT
 *  sign-in is Codex's). */
export const AGENTS = REGISTRY_AGENTS;
export const AGENT_OF_NEED = Object.freeze(Object.fromEntries(AGENT_LINES.flatMap((l) => [[l.id, l.agent], ...(l.signIn ? [[l.signIn, l.agent]] : [])])));
/** The agents a live entry can name as the one it drives (`agent`) or as its
 *  U-LLM (`ullm`): every agent line, the --agents names plus OpenCode's second
 *  generation, which --agents counts as opencode (test-organization.md §5). */
export const LIVE_AGENTS = LINES;
const agentFamily = agentOfLine;
/** The agent(s) an entry names in `agent`, as a list (none when it names none). */
export const namedAgents = (x) => (x.agent == null ? [] : [x.agent].flat());
/** The agents an entry drives, sorted: its `agent` and `ullm` when it names
 *  them, else derived from its needs (the agent's CLI or its login). */
export const entryAgents = (x) => x.agent != null
  ? [...new Set([...namedAgents(x), ...(x.ullm ? [x.ullm] : [])].map(agentFamily))].sort()
  : [...new Set((x.needs ?? []).map((n) => AGENT_OF_NEED[n]).filter(Boolean))].sort();
/** A drill entry (the watch-run catalog, test-organization.md §7.2). */
export const isDrill = (x) => x.id.startsWith("drill.");
/** An entry whose live runs record into the watch store: a drill entry, or
 *  one that says so (`watchStore: true`, the demo battery): run-suites
 *  appends `--store <the watch store>` to its command. */
export const recordsLive = (x) => isDrill(x) || x.watchStore === true;
export const AXES = ["secrets", "off", "injection", "full"];
export const PLATFORMS = ["linux", "darwin"];

/** The `needs` vocabulary. */
export const NEEDS = {
  // The kernel lane (test-reorganization.md §3: a need, not a kind): the entry
  // runs in the per-push kernel guest, never inside the per-entry sandbox; its
  // other needs name the mechanisms (userns, bwrap, landlock, seccomp, native-bins).
  kernel: "the kernel lane: the per-push kernel guest (user namespaces, bwrap, Landlock, seccomp, the kernel-feature binaries)",
  node: "node + npm (the package's node_modules installed)",
  cargo: "the Rust toolchain",
  bash: "bash and the base shell tools",
  git: "git",
  curl: "curl",
  openssl: "the openssl CLI",
  script: "util-linux script(1), a PTY",
  nc: "netcat",
  python3: "python3",
  tmux: "tmux",
  bwrap: "bubblewrap",
  userns: "unprivileged user namespaces",
  landlock: "Landlock (ABI 4 for TCP, kernel >= 6.7)",
  seccomp: "seccomp user notification",
  "native-bins": "the kernel-feature binaries (scripts/build-native.sh)",
  claude: "the claude CLI",
  codex: "the codex CLI",
  openclaw: "the openclaw CLI",
  opencode: "the opencode CLI",
  opencode2: "the OpenCode 2 CLI (npm @opencode/cli: `opencode2` on PATH, or MANDU_OPENCODE_V2_BIN; the CI guest pins it, scripts/ci/pins.env)",
  goose: "the goose CLI (the release binary, scripts/ci/pins.env)",
  "cargo-audit": "cargo-audit (the release binary, scripts/ci/pins.env CARGO_AUDIT_VERSION; or CARGO_AUDIT=<path>)",
  ollama: "a local Ollama with the test model pulled",
  // Which credential an entry authenticates with decides its nightly lane
  // (continuous-integration.md §9.8); the four are not interchangeable.
  "claude-login": "a Claude subscription login ($HOME/.claude/.credentials.json; an API key does not serve)",
  "chatgpt-login": "a Codex ChatGPT sign-in, reduced (no refresh token): its auth.json at MANDU_CI_CODEX_AUTH (an API key does not serve)",
  "anthropic-api-key": "an Anthropic API key (sk-ant-api… or sk-ant-usr…) in ANTHROPIC_API_KEY (spends API budget)",
  "openai-api-key": "an OpenAI API key in OPENAI_API_KEY (spends API budget)",
  "typesafe-api-key": "a TypeSafe API key (jev-ultrafast's decision model) in TYPESAFE_API_KEY or Mandu's secrets file (spends API budget)",
  "openrouter-api-key": "an OpenRouter API key in OPENROUTER_API_KEY or Mandu's secrets file (spends API budget)",
  chromium: "a headless Chromium (MANDU_TEST_CHROMIUM, or Playwright's headless shell in ~/.cache/ms-playwright)",
  kvm: "/dev/kvm",
  qemu: "qemu-system-x86_64, qemu-img",
  network: "network access (the install kind's image downloads)",
  "cli-latest": "the newest released agent CLI, installed over the pinned one",
  "timing-baseline": "a host as fast as the one the suite's recorded timings came from (the CI guest; runtime-instances.md §14.11)",
};

/** The needs that make an env suite's result the host's (test-reorganization.md §3): an env
 *  entry names at least one, or reaches the internet. */
export const ENV_NEEDS = ["ollama", "claude-login", "chatgpt-login", "anthropic-api-key", "openai-api-key", "cli-latest", "timing-baseline"];

/** The properties a suite can prove (test-reorganization.md §5.1): each a path in or out of
 *  the model, or a mechanism the invariant leans on. */
export const PROPERTIES = [
  "model-ingress/file", "model-ingress/exec-output", "model-ingress/web", "model-ingress/mcp", "model-ingress/git",
  "model-ingress/prompt",
  "reply/desymbolize",
  "network-egress/upload", "network-egress/dns", "network-egress/mitm",
  "fs/open-raw", "fs/twin", "fs/agentview",
  "exec/symbol-command", "exec/provenance", "exec/box",
  "git-history/locked-path", "git-history/locked-blob",
  "ullm/quarantine", "ullm/local-endpoint",
  "policy/monotonic", "policy/suggestion",
  "launcher/confine", "launcher/fail-closed",
  "utility/no-over-block", "utility/task",
];

/** A unit, component or stack entry needs nothing beyond node, cargo and base shell tools. */
export const OFFLINE_NEEDS = new Set(["node", "cargo", "bash", "git", "curl", "openssl", "script", "nc"]);

/** The kinds whose entries run the launcher's native bins (a sandbox suite
 *  names them; a replay-drill's launch wraps its agent with them too). */
export const NATIVE_BIN_KINDS = new Set(["replay-drill", "sandbox"]);

/**
 * Whether an entry runs the kernel-feature bins that scripts/build-native.sh
 * builds: it is a replay-drill or sandbox entry outside the frozen lane, or it
 * needs `native-bins` (a live-drill, a frozen-lane entry). scripts/test-all.sh
 * builds them first when a selected entry does (test-organization.md §3).
 */
export function usesNativeBins(x) {
  return (!x.frozen && NATIVE_BIN_KINDS.has(x.kind)) || (x.needs ?? []).includes("native-bins");
}

// ── loading ────────────────────────────────────────────────────────────────────

/** The manifest's entries (+ private/suites.mjs when present) and its
 *  aggregates. `privateProblems` is the private manifest's own part of
 *  `check` (its `problems(root)`, the problems it reports as `drill: …`), or
 *  null. `scopes` are the MR lane's scopes both manifests declare
 *  (scripts/ci/lane.mjs, continuous-integration.md §5.8). */
export async function loadManifest({ root = REPO_ROOT, includePrivate = true } = {}) {
  const pub = await import(pathToFileURL(join(root, "tests", "suites.mjs")).href);
  const entries = [...(pub.entries ?? pub.default)];
  const aggregates = [...(pub.aggregates ?? [])];
  const scopes = [...(pub.scopes ?? [])];
  const privPath = join(root, "private", "suites.mjs");
  let privateLoaded = false;
  let privateProblems = null;
  if (includePrivate && existsSync(privPath)) {
    const priv = await import(pathToFileURL(privPath).href);
    for (const x of priv.entries ?? priv.default ?? []) entries.push({ ...x, private: true });
    scopes.push(...(priv.scopes ?? []));
    privateLoaded = true;
    if (typeof priv.problems === "function") privateProblems = priv.problems;
  }
  return { entries, aggregates, scopes, privateLoaded, privateProblems };
}

const splitList = (v) => (v == null ? [] : String(v).split(",").map((s) => s.trim()).filter(Boolean));

function idMatcher(pattern) {
  if (!pattern.includes("*")) return (id) => id === pattern;
  const re = new RegExp(`^${pattern.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
  return (id) => re.test(id);
}

/**
 * Expand `shards` (test-organization.md §5): an entry that declares
 * `shards: [{ id, cmd?, env?, timeout? }]` runs as those shards, each its own
 * entry `<id>.<shard id>` with the parent's fields and the shard's cmd / env /
 * timeout on top, so the runner can run them side by side. The parent keeps
 * its claims (the completeness check reads the unexpanded manifest).
 */
export function expandShards(entries) {
  const out = [];
  for (const x of entries) {
    if (!Array.isArray(x.shards) || !x.shards.length) { out.push(x); continue; }
    const { shards, ...base } = x;
    for (const sh of shards) {
      out.push({
        ...base, id: `${x.id}.${sh.id}`, shardOf: x.id,
        ...(sh.cmd ? { cmd: sh.cmd } : {}),
        env: { ...(x.env ?? {}), ...(sh.env ?? {}) },
        timeout: sh.timeout ?? x.timeout,
        ...(sh.queueAs != null ? { queueAs: sh.queueAs } : {}),
      });
    }
  }
  return out;
}

/**
 * Select entries. `only` (ids, `*` allowed) picks exactly those entries whatever
 * their kind, frozen, flaky or internet flag (naming an entry is selecting it);
 * without it, `kinds` picks and flaky / internet entries stay out unless included.
 * A frozen entry never runs with its kind: `frozen` adds every frozen entry
 * (the integrity lane, protection-modes.md §10), whatever its kind.
 * `flakyKinds` adds the flaky entries (only those) of more kinds: the nightly
 * runs the nightly kinds plus every flaky entry (continuous-integration.md §9).
 * A `manual` entry (its value the reason) never runs with its kind, only when
 * named, and is reported as excluded with that reason.
 * `lane` (the nightly's `subscription` or `api-key`, continuous-integration.md §9.8)
 * keeps only the entries whose `credential` is that; an entry with none (it
 * needs no login) is in the subscription lane (inLane).
 * `need` (null = any): keeps only the entries whose needs include it (the
 * kernel guest's job runs `--need kernel`: every kernel-lane entry, sandbox or
 * replay-drill, test-reorganization.md §3).
 * `agents` (null = any): keeps an entry only when every agent it drives
 * (entryAgents) is in the list; an entry that drives none stays.
 * `drills` (null = all): narrows each drill entry's scenario list (its
 * `select`, narrowSelect) to those ids; a drill entry left with none is
 * excluded. `drills` with no kinds, no `frozen` and no `only` selects the
 * drill catalog's entries alone (the `drill.*` live-drills outside the frozen
 * lane), not every live-drill. An id no drill entry of the manifest runs is returned in
 * `unknownDrills`.
 * An entry's `aliases` (its ids before a rename) select it as its id does.
 * A platform mismatch always excludes. Returns { selected, excluded, unknown, unknownDrills }.
 */
export function selectEntries(entries, { kinds = [], frozen = false, need = null, only = [], platform = process.platform, includeFlaky = false, includeInternet = false, unsharded = false, flakyKinds = [], lane = null, agents = null, drills = null } = {}) {
  const selected = [];
  const excluded = [];
  const knownDrills = new Set(entries.filter(isDrill).flatMap((x) => x.select?.values ?? []));
  const unknownDrills = drills ? drills.filter((d) => !knownDrills.has(d)) : [];
  const matchers = only.map((p) => ({ p, m: idMatcher(p), hit: false }));
  const drillsAlone = Boolean(drills) && !kinds.length && !frozen && !only.length;
  // `unsharded`: the entries as declared (a sharded entry is one entry and keeps
  // its `shards` array), for a reader that runs an entry whole (the dashboard).
  for (let x of unsharded ? entries : expandShards(entries)) {
    if (matchers.length) {
      // Naming a sharded entry selects every shard of it.
      const hits = matchers.filter((o) => o.m(x.id) || (x.shardOf != null && o.m(x.shardOf)) || (x.aliases ?? []).some((a) => o.m(a)));
      if (!hits.length) continue;
      for (const h of hits) h.hit = true;
    } else {
      const inRun = x.frozen ? frozen : drillsAlone ? x.kind === "live-drill" && isDrill(x) : kinds.includes(x.kind);
      // A `nightly` entry rides with the flaky ones: the nightly's
      // --flaky-kinds takes it, its kind's per-push run never does.
      const extraFlaky = !x.frozen && (Boolean(x.flaky) || x.nightly != null) && flakyKinds.includes(x.kind);
      if ((!inRun && !extraFlaky) || x.idOnly === true) continue;
      if (x.manual) { excluded.push({ id: x.id, reason: `manual: ${x.manual}` }); continue; }
      if (x.nightly != null && !extraFlaky) { excluded.push({ id: x.id, reason: `nightly: ${x.nightly}` }); continue; }
      if (x.flaky && !includeFlaky && !extraFlaky) { excluded.push({ id: x.id, reason: `flaky: ${x.flaky.reason}` }); continue; }
      if (x.internet && !includeInternet) { excluded.push({ id: x.id, reason: "internet (--include-internet)" }); continue; }
    }
    if (lane && !inLane(x, lane)) {
      excluded.push({ id: x.id, reason: x.credential ? `credential ${x.credential} (this run: ${lane})` : `no credential: the subscription lane runs it (this run: ${lane})` });
      continue;
    }
    if (need && !(x.needs ?? []).includes(need)) { excluded.push({ id: x.id, reason: `does not need ${need} (this run: --need ${need})` }); continue; }
    if (agents) {
      const outside = entryAgents(x).filter((a) => !agents.includes(a));
      if (outside.length) { excluded.push({ id: x.id, reason: `drives ${outside.join(",")} (this run: --agents ${agents.join(",")})` }); continue; }
    }
    if (drills && isDrill(x) && x.select) {
      const narrowed = narrowSelect(x, drills);
      if (!narrowed) { excluded.push({ id: x.id, reason: `none of its scenarios in --drills ${drills.join(",")}` }); continue; }
      x = narrowed;
    }
    if (platform && !(x.platforms ?? ["linux"]).includes(platform)) {
      excluded.push({ id: x.id, reason: `platforms ${(x.platforms ?? []).join(",")} (this is ${platform})` });
      continue;
    }
    selected.push(x);
  }
  const unknown = matchers.filter((o) => !o.hit).map((o) => o.p);
  return { selected, excluded, unknown, unknownDrills };
}

/**
 * An entry with its scenario subset (`select`) narrowed to `wanted`, or null
 * when none of its scenarios is wanted. `select` names where the list lives:
 * `{ env, values }` (an env variable holding the comma list, the claude-e2e
 * cuts' MANDU_E2E_ONLY) or `{ arg, values }` (the argument after `arg` in
 * `cmd`, the drills' `--ids`). The copy's list keeps the entry's own order.
 * An entry with no `select` is returned unchanged.
 */
export function narrowSelect(x, wanted) {
  if (!x.select) return x;
  const values = x.select.values.filter((v) => wanted.includes(v));
  if (!values.length) return null;
  const list = values.join(",");
  const out = { ...x, select: { ...x.select, values } };
  if (x.select.env) out.env = { ...x.env, [x.select.env]: list };
  if (x.select.arg) {
    const i = x.cmd.indexOf(x.select.arg);
    out.cmd = [...x.cmd.slice(0, i + 1), list, ...x.cmd.slice(i + 2)];
  }
  return out;
}

/**
 * The phases of a run (continuous-integration.md §5): `parallel`, the entries outside
 * the kernel lane that are safe side by side ("sandbox" ones only when each entry
 * runs in the sandbox); `serial`, the other such entries, one at a time;
 * `kernel`, the entries that need `kernel` marked `parallel: true` (safe beside
 * each other: no fixed port, no shared path), and `kernelSerial`, the rest of the
 * kernel lane, each alone within it. Kernel-lane entries never run in the
 * sandbox, so "sandbox" is not parallel for them. Manifest order within each
 * phase. The runner decides when each phase runs (scripts/run-suites.mjs).
 */
export function planPhases(selected, { sandboxed = false } = {}) {
  const parallel = [];
  const serial = [];
  const kernel = [];
  const kernelSerial = [];
  for (const x of selected) {
    if (needsKernel(x)) (x.parallel === true ? kernel : kernelSerial).push(x);
    else if (x.parallel === true || (x.parallel === "sandbox" && sandboxed)) parallel.push(x);
    else serial.push(x);
  }
  return { parallel, serial, kernel, kernelSerial };
}

/**
 * Entry costs (continuous-integration.md §5.4): seconds per entry id from a green
 * per-push run, checked in as tests/suite-costs.json (the public manifest's
 * entries) and private/suite-costs.json (private/suites.mjs's, so the public
 * snapshot's table names only entries it has), regenerated with
 * `node scripts/suites.mjs costs [--private] <runs dir>` (each entry's median
 * over the recent green full runs). A CI run orders by fresher numbers:
 * vm-run.sh measures the same medians from its host's runs and the guest
 * passes them as run-suites --costs, over these tables. They only ORDER
 * the runner's queue (longest first); a stale or missing table changes when an
 * entry starts, never whether it runs or how it is judged.
 */
export const COSTS_FILE = join("tests", "suite-costs.json");
export const PRIVATE_COSTS_FILE = join("private", "suite-costs.json");
/** The cost of an entry the table does not know yet (a new entry or shard). */
export const DEFAULT_COST = 30;

/** The cost table at `file`; the default file may be absent (every entry then costs the same). */
export function loadCosts(file = join(REPO_ROOT, COSTS_FILE), { required = false } = {}) {
  if (!existsSync(file)) {
    if (required) throw new Error(`cost table '${file}' not found`);
    return {};
  }
  let c;
  try { c = JSON.parse(readFileSync(file, "utf8")); } catch (e) { throw new Error(`cost table '${file}': ${e.message}`); }
  if (!c || typeof c !== "object" || Array.isArray(c)) throw new Error(`cost table '${file}': not an object of seconds by entry id`);
  for (const [id, v] of Object.entries(c)) {
    if (!(typeof v === "number" && Number.isFinite(v) && v >= 0)) throw new Error(`cost table '${file}': '${id}' is not a number of seconds`);
  }
  return c;
}

/** Both default tables of the tree at `root` (each may be absent). */
export function loadAllCosts(root = REPO_ROOT) {
  return { ...loadCosts(join(root, COSTS_FILE)), ...loadCosts(join(root, PRIVATE_COSTS_FILE)) };
}

/** An entry's place in the queue: its `queueAs` when the manifest pins one
 *  (a shard that must not start in the opening burst, test-reorganization.md
 *  §6.9), else the table's cost, else DEFAULT_COST. */
export const costOf = (x, costs) => x.queueAs ?? costs[x.id] ?? DEFAULT_COST;

/** Longest first; entries of equal cost keep their manifest order. `weight`
 *  scales an entry's cost for the order only (sharedQueueOrder). */
export function orderByCost(xs, costs, weight = () => 1) {
  const key = (x) => costOf(x, costs) * weight(x);
  return xs.map((x, i) => [x, i]).sort((a, b) => key(b[0]) - key(a[0]) || a[1] - b[1]).map(([x]) => x);
}

/** The sandboxed run's one queue (continuous-integration.md §5.4): longest
 *  first, a kernel entry's cost weighted by slots ÷ kernelJobs. The kernel
 *  entries go through a lane `kernelJobs` wide, so by their own cost they
 *  started late and the last of them drained three at a time while the other
 *  slots idled (~35 s a run, 2026-10-18); weighted, the lane's work starts as
 *  early as an entry `slots ÷ kernelJobs` times as long would. Orders only. */
export function sharedQueueOrder(xs, costs, { slots, kernelJobs, isKernel }) {
  const w = Math.max(1, slots / Math.max(1, kernelJobs));
  return orderByCost(xs, costs, (x) => (isKernel(x) ? w : 1));
}

/** The cost table from a run's summary.json: every entry that ran (and that
 *  `keep` accepts, when given), seconds to one decimal, ids sorted. */
export function costsFromSummary(summary, keep = () => true) {
  if (!summary || !Array.isArray(summary.entries)) throw new Error("not a run summary (no entries)");
  const out = {};
  for (const e of [...summary.entries].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))) {
    if (typeof e.duration_s === "number" && ["pass", "fail", "timeout"].includes(e.result) && keep(e.id)) out[e.id] = Math.round(e.duration_s * 10) / 10;
  }
  return out;
}

/** How many recent green full runs `costsFromRuns` takes by default. */
export const COSTS_LAST_RUNS = 10;
/** A run is a full per-push run when it ran at least this share of the
 *  largest green run's entries (a docs-lane run, an --only run, the nightly
 *  and the Linux 7.0 kernel job run a handful and are left out). */
export const COSTS_FULL_SHARE = 0.9;

/** The cost table from many runs' summaries (continuous-integration.md §5.4):
 *  of the green (`result: pass`) runs, the full per-push ones (see
 *  COSTS_FULL_SHARE), the `last` most recent by `started`; each entry's
 *  median duration over those runs where it passed (and that `keep`
 *  accepts), seconds to one decimal, ids sorted. Summaries that are not run
 *  summaries are ignored; none left gives an empty table. */
export function costsFromRuns(summaries, { last = COSTS_LAST_RUNS, keep = () => true } = {}) {
  const green = summaries.filter((s) => s && typeof s === "object" && s.result === "pass" && Array.isArray(s.entries));
  const most = Math.max(0, ...green.map((s) => s.entries.length));
  const runs = green
    .filter((s) => s.entries.length > 0 && s.entries.length >= COSTS_FULL_SHARE * most)
    .sort((a, b) => String(b.started ?? "").localeCompare(String(a.started ?? "")))
    .slice(0, last);
  const seen = new Map();
  for (const s of runs) {
    for (const e of s.entries) {
      if (!(e && typeof e.id === "string" && e.result === "pass" && typeof e.duration_s === "number" && Number.isFinite(e.duration_s) && e.duration_s >= 0)) continue;
      if (!keep(e.id)) continue;
      if (!seen.has(e.id)) seen.set(e.id, []);
      seen.get(e.id).push(e.duration_s);
    }
  }
  const out = {};
  for (const id of [...seen.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
    const d = seen.get(id).sort((a, b) => a - b);
    const m = d.length % 2 ? d[(d.length - 1) / 2] : (d[d.length / 2 - 1] + d[d.length / 2]) / 2;
    out[id] = Math.round(m * 10) / 10;
  }
  return out;
}

/** The summaries named on the command line: a summary.json file, or a runs
 *  directory (`ci-runs`, one directory per run), whose `<run>/summary.json`
 *  files are read; one that is unreadable or not JSON is skipped. */
export function readSummaries(paths) {
  const out = [];
  const read = (f) => { try { out.push(JSON.parse(readFileSync(f, "utf8"))); } catch { /* not a summary */ } };
  for (const p of paths) {
    if (!existsSync(p)) throw new Error(`'${p}' not found`);
    if (statSync(p).isDirectory()) {
      for (const d of readdirSync(p).sort()) {
        const f = join(p, d, "summary.json");
        if (existsSync(f)) read(f);
      }
    } else {
      out.push(JSON.parse(readFileSync(p, "utf8")));
    }
  }
  return out;
}

/** Directories (repo-relative) holding a package.json among the entries' cwds: what to `npm ci`. */
export function packageDirs(entries, root = REPO_ROOT) {
  const dirs = [];
  for (const x of entries) {
    const d = x.cwd ?? ".";
    if (d !== "." && existsSync(join(root, d, "package.json")) && !dirs.includes(d)) dirs.push(d);
  }
  return dirs;
}

// ── claims ─────────────────────────────────────────────────────────────────────

const toPosix = (p) => p.split(sep).join("/");
const EXCLUDED_DIRS = new Set(["node_modules", "target", ".git", "private", "dist", ".mandu"]);

/** Expand a glob (`*` within a segment, `**` across segments) relative to `base`; repo-relative results. */
export function expandGlob(pattern, base, root = REPO_ROOT) {
  const abs = toPosix(resolve(base, pattern));
  if (!pattern.includes("*")) return existsSync(abs) ? [toPosix(relative(root, abs))] : [];
  const segs = abs.split("/");
  const out = [];
  const walk = (dir, i) => {
    if (i === segs.length) { out.push(dir); return; }
    const seg = segs[i];
    if (!seg.includes("*")) { const n = `${dir}/${seg}`; if (existsSync(n)) walk(n, i + 1); return; }
    let names;
    try { names = readdirSync(dir || "/", { withFileTypes: true }); } catch { return; }
    if (seg === "**") {
      walk(dir, i + 1);
      for (const d of names) if (d.isDirectory() && !EXCLUDED_DIRS.has(d.name)) walk(`${dir}/${d.name}`, i);
      return;
    }
    const re = new RegExp(`^${seg.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join("[^/]*")}$`);
    for (const d of names) if (re.test(d.name)) walk(`${dir}/${d.name}`, i + 1);
  };
  walk("", 1);
  return out.filter((p) => { try { return statSync(p).isFile(); } catch { return false; } })
    .map((p) => toPosix(relative(root, p))).sort();
}

const PATHLIKE = /\.(ts|mts|mjs|js|sh)$/;

/** Path-like tokens of an npm script body (env assignments, flags and programs dropped). */
export function scriptPathTokens(body) {
  return body.split(/\s+|&&|;|\|\|/).filter((t) => t && !t.startsWith("-") && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t) && (PATHLIKE.test(t) || t.includes("*")));
}

function readPkgScripts(root, cwd) {
  const p = join(root, cwd, "package.json");
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, "utf8")).scripts ?? {}; } catch { return null; }
}

/** The npm script an entry's cmd runs, or null. */
export function npmScriptOf(cmd) {
  if (cmd[0] !== "npm") return null;
  if (cmd[1] === "test" || cmd[1] === "t") return "test";
  if (cmd[1] === "run" || cmd[1] === "run-script") return cmd[2] ?? null;
  return null;
}

/**
 * What an entry claims: { files (repo-relative), scripts ("<cwd>#<name>"), missing (problems) }.
 * A variant (variantOf) claims only its npm scripts; `{ runs: true }` keeps the
 * files its cmd names (what it runs, not what it claims).
 */
export function entryClaims(x, root = REPO_ROOT, { runs = false } = {}) {
  const files = new Set();
  const scripts = new Set();
  const missing = [];
  const cwd = x.cwd ?? ".";
  const base = join(root, cwd);
  const pkgScripts = readPkgScripts(root, cwd);
  const own = npmScriptOf(x.cmd ?? []);
  const names = [...(own ? [own] : []), ...(x.scripts ?? [])];
  for (const n of names) {
    if (!pkgScripts || pkgScripts[n] == null) { missing.push(`npm script '${n}' not in ${cwd}/package.json`); continue; }
    scripts.add(`${cwd}#${n}`);
  }
  const claimFile = (tok, from) => {
    const hits = expandGlob(tok, from, root);
    if (!hits.length) missing.push(`path '${tok}' (from ${toPosix(relative(root, from)) || "."}) matches nothing`);
    for (const h of hits) files.add(h);
  };
  for (const tok of (x.cmd ?? []).slice(own ? 3 : 0)) {
    if (/\s/.test(tok) || tok.startsWith("-")) continue;
    if (PATHLIKE.test(tok) || tok.includes("*")) claimFile(tok, base);
  }
  if (own && pkgScripts?.[own] != null) for (const tok of scriptPathTokens(pkgScripts[own])) claimFile(tok, base);
  for (const f of x.files ?? []) claimFile(f, root);
  // A variant re-runs files its parent claims: it claims none, but `runs` (the
  // docs-lane sweep) wants the files it runs all the same.
  if (x.variantOf && !runs) files.clear();
  return { files, scripts, missing };
}

/** Every test file the check requires a claim for (§5), repo-relative. */
export function walkTestFiles(root = REPO_ROOT) {
  const out = [];
  const walk = (dir) => {
    for (const d of readdirSync(join(root, dir), { withFileTypes: true })) {
      if (d.isDirectory()) { if (!EXCLUDED_DIRS.has(d.name) && !d.name.startsWith(".")) walk(dir ? `${dir}/${d.name}` : d.name); continue; }
      const rel = dir ? `${dir}/${d.name}` : d.name;
      if (/\.test\.(ts|sh|mjs)$/.test(d.name)) out.push(rel);
      else if (dir === "scripts/test") out.push(rel);
      else if (dir === "tests/conformance/lib" && /^unit_.*\.ts$/.test(d.name)) out.push(rel);
      else if (rel === "tests/conformance/run.ts") out.push(rel);
      else if (dir === "scripts/matrix/suites" && d.name.endsWith(".sh")) out.push(rel);
    }
  };
  walk("");
  return out.sort();
}

/** Every `test*` npm script of every public package: "<dir>#<name>". */
export function listTestScripts(root = REPO_ROOT) {
  const out = [];
  const walk = (dir) => {
    for (const d of readdirSync(join(root, dir || "."), { withFileTypes: true })) {
      if (d.isDirectory()) { if (!EXCLUDED_DIRS.has(d.name) && !d.name.startsWith(".")) walk(dir ? `${dir}/${d.name}` : d.name); continue; }
      if (d.name !== "package.json" || !dir) continue;
      const s = readPkgScripts(root, dir) ?? {};
      for (const n of Object.keys(s)) if (/^test/.test(n)) out.push(`${dir}#${n}`);
    }
  };
  walk("");
  return out.sort();
}

/** The canaries protection-modes.md §10.5 names (the backticked paths of its "Default lane" bullet). */
export function freezeCanaries(root = REPO_ROOT) {
  const doc = readFileSync(join(root, "docs/design/architecture/protection-modes.md"), "utf8");
  const m = /\*\*Default lane\*\*[\s\S]*?\*\*canaries\*\*:?([\s\S]*?)\n- \*\*/.exec(doc);
  return m ? [...m[1].matchAll(/`([^`]+\.(?:ts|mjs|sh))`/g)].map((x) => x[1]) : [];
}

// ── the docs-lane sweep ────────────────────────────────────────────────────────
//
// The docs lane (continuous-integration.md §5.5) is what a documentation-only MR runs
// instead of the per-push kinds: the entries marked `docsLane`. A test that reads docs at
// run time and runs in no such entry is missed by that lane until the next full
// run on master, so the check sweeps the test files for run-time reads of the
// repository's docs and flags each one no docs-lane entry runs. A heuristic, kept
// narrow on purpose: it looks at code (comments stripped), and counts a path only
// when the repository has it:
//   - a string literal that is a whole `docs/…` path ("docs/design/x.md"), or
//   - a repo-root name joined with `docs` or a `*.md` name
//     (join(REPO, "docs"), join(ROOT, "README.md"), "$ROOT/docs/x.md"),
// and, in a JS/TS file, a filesystem read somewhere in it (readFileSync,
// readdirSync, existsSync, …). Two readers no path shows are caught by their
// own signal (2026-09-30; they sat on a hand-kept list before):
//   - `git ls-files` or `git grep` in a file that names a repo root: it reads
//     the tracked files, the docs among them;
//   - a module that reads docs on a caller's behalf says so in a comment,
//     `docs-reader:` and then the names a test reaches it by, each in
//     backticks (a function, a route); a test whose code names one reads that
//     module's docs. The marker is the module author's to add, and the
//     check asks for it (2026-10-17, unmarkedDocsReaders): the path
//     heuristic over each non-test module (comments stripped, a
//     `docsUrl("docs/…")` link not counted; six modules matched, all of them
//     writers, links or data) fails the check on one that reads docs and
//     carries no marker. Following the tests' imports instead flags the
//     whole closure of a server (continuous-integration.md §5.5).
// A file it flags wrongly says so in a comment: `docs-lane-exempt: <reason>`.

/** The opt-out: a comment naming why the file needs no docs-lane entry. A
 *  mention of the syntax (`docs-lane-exempt: <reason>`) is not one. */
export const DOCS_LANE_EXEMPT = /docs-lane-exempt:[ \t]*[^\s<`]/;

const ROOT_NAME = String.raw`(?:REPO|ROOT|REPO_ROOT|REPO_DIR|repoRoot|repo_root)`;
const DOCS_LITERAL = /["'`](?:\.\.?\/)*(docs\/[^"'`\s$]*)["'`]/g;
const ROOT_JOINED = new RegExp(
  String.raw`\b${ROOT_NAME}\s*,\s*["'\`]((?:docs|[\w.-]+\.md)(?:\/[^"'\`\s$]*)?)["'\`]` +
  String.raw`|\$\{?${ROOT_NAME}\}?\/((?:docs|[\w.-]+\.md)(?:\/[^"'\`\s$)]*)?)`, "g");
const READ_CALL = /\b(?:readFileSync|readFile|readdirSync|readdir|createReadStream|existsSync|statSync)\s*\(/;
const GIT_TRACKED = /\bls-files\b|\bgit(?:\s+-C\s+\S+|\s+--?[\w-]+(?:=\S+)?)*\s+grep\b|["'`]git["'`]\s*,\s*\[[^\]]*["'`]grep["'`]/;
const ROOT_REF = new RegExp(String.raw`\b${ROOT_NAME}\b`);
/** A docs-reader marker: the names a test reaches the module by, in backticks, on the marker's line. */
export const DOCS_READER = /docs-reader:((?:[ \t,]*`[^`\n]+`)+)/;
const CODE_FILE = /\.(?:ts|mts|mjs|js|sh)$/;

/** Code without its comments: `//` and block comments in JS/TS, `#` in shell.
 *  Rough, and enough here. A block comment keeps its newlines, so a line of
 *  the code is the same line of the file. */
function codeOf(text, shell) {
  if (shell) return text.replace(/(^|\s)#(?![!{]).*$/gm, "$1");
  return text.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, "")).replace(/(^|[\s;{}(),])\/\/.*$/gm, "$1");
}

/** The names a module's `docs-reader:` marker lists ([] without one); the
 *  marker counts only on a comment line. */
function readerNames(text) {
  const names = [];
  if (!text.includes("docs-reader:")) return names;
  for (const line of text.split("\n")) {
    if (!/^\s*(?:\/\/|\/?\*|#(?!!))/.test(line)) continue;
    const m = DOCS_READER.exec(line);
    if (m) for (const n of m[1].matchAll(/`([^`\n]+)`/g)) names.push(n[1]);
  }
  return names;
}

/** Every non-test code file outside the excluded directories: [{ rel, text }]. */
function nonTestCode(root) {
  const tests = new Set(walkTestFiles(root));
  const out = [];
  const walk = (dir) => {
    for (const d of readdirSync(join(root, dir || "."), { withFileTypes: true })) {
      const rel = dir ? `${dir}/${d.name}` : d.name;
      if (d.isDirectory()) { if (!EXCLUDED_DIRS.has(d.name) && !d.name.startsWith(".")) walk(rel); continue; }
      if (!CODE_FILE.test(d.name) || tests.has(rel)) continue;
      let text;
      try { text = readFileSync(join(root, rel), "utf8"); } catch { continue; }
      out.push({ rel, text });
    }
  };
  walk("");
  return out.sort((a, b) => (a.rel < b.rel ? -1 : 1));
}

/**
 * The modules that declare a `docs-reader:` marker: [{ module, names }], the
 * names in backticks after it. Every non-test code file outside the excluded
 * directories is looked at; the marker counts only on a comment line.
 */
export function docsReaderModules(root = REPO_ROOT) {
  const out = [];
  for (const { rel, text } of nonTestCode(root)) {
    const names = readerNames(text);
    if (names.length) out.push({ module: rel, names });
  }
  return out;
}

/** A link to a doc, not a read of it: `docsUrl("docs/x.md")` and the like. */
const LINK_CALL = /\b\w*(?:Url|URL|Link|Href)\(\s*["'`][^"'`\n]*["'`]/g;

/**
 * The marker's own check (2026-10-17): the non-test modules that read the
 * repository's docs at run time, by docsReads' path heuristic over their code
 * (a link such as `docsUrl("docs/x.md")` left out; the git signal is the
 * tests'), and declare neither a `docs-reader:` marker nor a
 * `docs-lane-exempt: <reason>`. Without the marker, a test that reaches such
 * a module (importing it, calling its route) reads docs and the sweep cannot
 * see it, so the check fails CLOSED on the module: [{ module, line, reads }],
 * `line` the first line of the file whose code names a path it reads.
 * Following imports from the tests was tried and rejected
 * (continuous-integration.md §5.5); this asks the module once instead.
 */
export function unmarkedDocsReaders(root = REPO_ROOT) {
  const out = [];
  for (const { rel, text } of nonTestCode(root)) {
    if (readerNames(text).length || DOCS_LANE_EXEMPT.test(text)) continue;
    const unlinked = text.replace(LINK_CALL, (m) => m.replace(/["'`][^"'`\n]*["'`]$/, '""'));
    const reads = docsReads(unlinked, rel, root, []).filter((r) => r !== "git ls-files");
    if (!reads.length) continue;
    const lines = codeOf(unlinked, rel.endsWith(".sh")).split("\n");
    const at = lines.findIndex((l) => [...l.matchAll(DOCS_LITERAL), ...l.matchAll(ROOT_JOINED)].some((m) => reads.includes((m[1] ?? m[2] ?? "").replace(/\/+$/, ""))));
    out.push({ module: rel, line: at + 1 || 1, reads });
  }
  return out;
}

/**
 * The repository docs paths a test file reads at run time, by the heuristic
 * above (repo-relative, sorted), plus "git ls-files" and "<module> (<name>)"
 * for the two signals; [] when it reads none. `file` is the path the text came
 * from (its extension picks the comment syntax); `readers` is
 * docsReaderModules().
 */
export function docsReads(text, file, root = REPO_ROOT, readers = []) {
  const shell = file.endsWith(".sh");
  const code = codeOf(text, shell);
  const out = new Set();
  if (GIT_TRACKED.test(code) && ROOT_REF.test(code)) out.add("git ls-files");
  for (const { module, names } of readers) {
    const hit = names.find((n) => code.includes(n));
    if (hit && module !== file) out.add(`${module} (${hit})`);
  }
  if (!shell && !READ_CALL.test(code)) return [...out].sort();
  const isDocs = (p) => p === "docs" || p.startsWith("docs/") || /\.md$/i.test(p);
  const keep = (p) => {
    const q = p.replace(/\/+$/, "");
    if (q && isDocs(q) && existsSync(join(root, q))) out.add(q);
  };
  for (const m of code.matchAll(DOCS_LITERAL)) keep(m[1]);
  for (const m of code.matchAll(ROOT_JOINED)) keep(m[1] ?? m[2]);
  return [...out].sort();
}

/**
 * The docs-lane sweep: every test file a per-push entry runs (the lane holds
 * per-push entries only) that reads docs at run time (docsReads) and that no
 * docs-lane entry runs. Returns { unclaimed: [{ file, reads }], exempt: [file] }.
 */
export function docsLaneSweep(entries, root = REPO_ROOT) {
  const readers = docsReaderModules(root);
  const inLane = new Set();
  const perPush = new Set();
  for (const x of entries) {
    if (x.docsLane === true) for (const f of entryClaims(x, root, { runs: true }).files) inLane.add(f);
    if (!x.frozen && PER_PUSH_KINDS.includes(x.kind)) for (const f of entryClaims(x, root).files) perPush.add(f);
  }
  const unclaimed = [];
  const exempt = [];
  for (const f of walkTestFiles(root)) {
    if (!perPush.has(f) || inLane.has(f)) continue;
    let text;
    try { text = readFileSync(join(root, f), "utf8"); } catch { continue; }
    const reads = docsReads(text, f, root, readers);
    if (!reads.length) continue;
    if (DOCS_LANE_EXEMPT.test(text)) exempt.push(f);
    else unclaimed.push({ file: f, reads });
  }
  return { unclaimed, exempt };
}

// ── the completeness check ─────────────────────────────────────────────────────

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * The flaky budget (test-organization.md §10): a flaky entry carries a reason,
 * the date it went flaky (`since`), the date it is next looked at (`revisit`),
 * and how many revisits it has already had (`revisits`, default 0). A flag
 * that outlives two revisits is an error: fix the suite or delete it. A
 * revisit date in the past is only a note, never an error: an unrelated push
 * must not fail because a calendar date passed.
 */
export function flakyBudget(flaky, today = new Date().toISOString().slice(0, 10)) {
  const errors = [];
  const notes = [];
  if (!flaky.reason) errors.push("flaky needs a reason");
  if (!ISO_DATE.test(flaky.since ?? "")) errors.push("flaky needs since: \"YYYY-MM-DD\"");
  if (!ISO_DATE.test(flaky.revisit ?? "")) errors.push("flaky needs revisit: \"YYYY-MM-DD\" (the date it is next looked at)");
  else if (ISO_DATE.test(flaky.since ?? "") && flaky.revisit <= flaky.since) errors.push("flaky revisit must come after since");
  const revisits = flaky.revisits ?? 0;
  if (!Number.isInteger(revisits) || revisits < 0) errors.push("flaky revisits must be a count");
  else if (revisits >= 2) errors.push(`flaky has outlived ${revisits} revisits: fix the suite or delete it (test-organization.md §10)`);
  if (ISO_DATE.test(flaky.revisit ?? "") && flaky.revisit < today) notes.push(`flaky revisit overdue (due ${flaky.revisit})`);
  return { errors, notes };
}

/**
 * The completeness check (test-organization.md §5). Returns { errors, notes };
 * an empty `errors` is a pass. Private entries are validated but the claim
 * universe is the public tree only (the public manifest works without them).
 */
export function checkManifest(entries, aggregates = [], root = REPO_ROOT) {
  const errors = [];
  const notes = [];
  const err = (id, msg) => errors.push(`${id}: ${msg}`);
  const ids = new Set();
  const canaries = new Set(freezeCanaries(root));
  if (canaries.size === 0) errors.push("protection-modes.md §10.5: no canary list found");

  const fileClaims = new Map();
  const scriptClaims = new Map();
  const claim = (map, key, by) => { if (!map.has(key)) map.set(key, []); map.get(key).push(by); };

  for (const x of entries) {
    const id = x.id ?? "(no id)";
    if (!x.id || typeof x.id !== "string") err(id, "no id");
    else if (ids.has(x.id)) err(id, "duplicate id");
    else if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/.test(x.id)) err(id, "id must be [A-Za-z0-9._-], at most 120 characters (the CI summary's id rule)");
    ids.add(x.id);
    if ("tier" in x || "lane" in x || "byHand" in x) err(id, "tier, lane and byHand are now kind, credential and manual (test-reorganization.md §4)");
    if (!KINDS.includes(x.kind)) err(id, `kind '${x.kind}' is not one of ${KINDS.join(", ")}`);
    if (x.frozen != null && x.frozen !== true) err(id, "frozen is true or absent");
    if (x.proves != null) {
      if (!Array.isArray(x.proves) || !x.proves.length) err(id, "proves is a non-empty list of properties (or absent)");
      else {
        for (const pr of x.proves) if (!PROPERTIES.includes(pr)) err(id, `proves '${pr}', which is not a property (PROPERTIES, test-reorganization.md §5.1)`);
        if (new Set(x.proves).size !== x.proves.length) err(id, "proves lists a property twice");
      }
    }
    // A nightly-kind entry claims what it proves or says why it proves
    // nothing (`provesNone`, tests/suites.mjs NO_PROVES), so a new nightly
    // entry cannot go unclaimed unnoticed (test-reorganization.md §11.1).
    if (x.provesNone != null) {
      if (typeof x.provesNone !== "string" || !x.provesNone.trim() || x.provesNone.length > 300) err(id, "provesNone is a reason of at most 300 characters (or absent)");
      if (x.proves != null) err(id, "proves and provesNone together: an entry either claims properties or says why it proves none");
    } else if (NIGHTLY_KINDS.includes(x.kind) && !x.frozen && x.proves == null) {
      err(id, "a nightly entry claims `proves` (the properties its hard assertions check on the real path) or says why it proves none (`provesNone`, tests/suites.mjs NO_PROVES; test-reorganization.md §5.2)");
    }
    if (!AXES.includes(x.axis)) err(id, `axis '${x.axis}' is not one of ${AXES.join(", ")}`);
    if (!Array.isArray(x.cmd) || !x.cmd.length || x.cmd.some((t) => typeof t !== "string")) err(id, "cmd must be a non-empty argv array");
    if (!existsSync(join(root, x.cwd ?? "\0"))) err(id, `cwd '${x.cwd}' does not exist`);
    if (!(Number.isFinite(x.timeout) && x.timeout > 0)) err(id, "timeout (seconds) missing");
    if (![true, false, "sandbox"].includes(x.parallel)) err(id, "parallel must be true, false or \"sandbox\"");
    if (!Array.isArray(x.platforms) || !x.platforms.length || x.platforms.some((p) => !PLATFORMS.includes(p))) err(id, "platforms must be a subset of linux, darwin");
    if (!Array.isArray(x.needs)) err(id, "needs must be an array");
    for (const n of x.needs ?? []) if (!(n in NEEDS)) err(id, `unknown need '${n}'`);
    if (HOST_FREE_KINDS.includes(x.kind)) for (const n of x.needs ?? []) if (!OFFLINE_NEEDS.has(n)) err(id, `${x.kind} entry needs '${n}' (outside node/cargo/base shell tools)`);
    // A sandbox suite runs the real sandbox: the kernel lane (test-reorganization.md §3).
    if (x.kind === "sandbox" && !needsKernel(x)) err(id, "a sandbox entry needs `kernel` (it runs in the kernel lane)");
    if (needsKernel(x) && !["sandbox", "replay-drill", "stack"].includes(x.kind)) err(id, `kind ${x.kind} cannot carry the kernel need (sandbox, replay-drill or stack only)`);
    // An env suite's result is the host's: its needs (or `internet`) say which part.
    if (x.kind === "env" && !x.internet && !(x.needs ?? []).some((n) => ENV_NEEDS.includes(n))) {
      err(id, `an env entry names what the host decides: one of ${ENV_NEEDS.join(", ")} in needs, or internet`);
    }
    if (x.env && Object.values(x.env).some((v) => typeof v !== "string")) err(id, "env values must be strings");
    if (x.gate && !(x.env && x.gate in x.env)) err(id, `gate '${x.gate}' is not set in env (selecting the entry must run it)`);
    if (x.select != null) {
      const sel = x.select;
      const list = Array.isArray(sel.values) ? sel.values.join(",") : null;
      if (!list || sel.values.some((v) => typeof v !== "string" || !v || v.includes(","))) err(id, "select.values must be a non-empty list of scenario names");
      else if (Boolean(sel.env) === Boolean(sel.arg)) err(id, "select names exactly one of env or arg (where the scenario list lives)");
      else if (sel.env && x.env?.[sel.env] !== list) err(id, `select.env ${sel.env} must hold the list (${list})`);
      else if (sel.arg && x.cmd?.[x.cmd.indexOf(sel.arg) + 1] !== list) err(id, `select.arg ${sel.arg} must be followed in cmd by the list`);
    }
    if (isDrill(x) && !x.select?.arg) err(id, "a drill entry names its scenarios in select ({ arg: \"--ids\", values })");
    if (x.watchStore != null && (x.watchStore !== true || (x.kind !== "live-drill" && x.kind !== "replay-drill"))) err(id, "watchStore is true or absent, on a live-drill or replay-drill entry (its live runs record into the watch store)");
    // `aliases`: the entry's ids before a rename, which still select it
    // (--only, `run`), so a caller's old id keeps working (test-organization.md §5).
    if (x.aliases != null) {
      if (!Array.isArray(x.aliases) || !x.aliases.length) err(id, "aliases is a non-empty list of former ids (or absent)");
      else for (const a of x.aliases) {
        if (typeof a !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/.test(a)) err(id, `alias '${a}' is not an id`);
        else if (entries.some((y) => y.id === a)) err(id, `alias '${a}' is an entry's id`);
        else if (entries.some((y) => y !== x && (y.aliases ?? []).includes(a))) err(id, `alias '${a}' is another entry's alias too`);
      }
    }
    // The agent a live entry drives (test-organization.md §5): named, so a
    // result can say what it ran on, and its CLI among the needs.
    if (x.agent != null) {
      const named = namedAgents(x);
      if (!named.length || named.some((a) => !LIVE_AGENTS.includes(a)) || new Set(named).size !== named.length) {
        err(id, `agent is one of ${LIVE_AGENTS.join(", ")} (a list of distinct ones only on a frozen entry)`);
      } else if (Array.isArray(x.agent) && !x.frozen) err(id, "agent is a list only on a frozen entry: a live entry drives one agent");
      else for (const a of named) if (!(x.needs ?? []).includes(a)) err(id, `it drives ${a}: its needs name that CLI`);
    } else if (x.browserAgent != null) {
      // A browser agent (devtools-relay.md): not a registry agent (it calls
      // its own model services), named from its own short list instead.
      if (!BROWSER_AGENTS.includes(x.browserAgent)) err(id, `browserAgent is one of ${BROWSER_AGENTS.join(", ")}`);
      else if (x.kind !== "live-drill") err(id, "browserAgent names the browser agent a live-drill entry drives");
    } else if (x.kind === "live-drill") err(id, "a live-drill entry names the agent it drives (`agent`, test-organization.md §5; a browser agent: `browserAgent`)");
    if (x.ullm != null) {
      if (!LIVE_AGENTS.includes(x.ullm)) err(id, `ullm is one of ${LIVE_AGENTS.join(", ")}`);
      else if (x.agent == null) err(id, "ullm (the agent serving as the U-LLM) needs an agent");
      else if (namedAgents(x).includes(x.ullm)) err(id, "ullm names another agent than the one it drives (leave it out when the agent is its own U-LLM)");
      else if (!(x.needs ?? []).includes(x.ullm)) err(id, `its U-LLM is ${x.ullm}: its needs name that CLI`);
    }
    if (x.flaky != null) {
      const b = flakyBudget(x.flaky);
      for (const e of b.errors) err(id, e);
      for (const n of b.notes) notes.push(`${id}: ${n}`);
    }
    // The nightly's two lanes (continuous-integration.md §9.8), one per credential:
    // every entry a nightly runs that needs a login names exactly one, so each
    // lane holds one kind of login; one that needs none names none, and the
    // subscription lane runs it (test-reorganization.md §8 step 2).
    if (x.credential != null && !CREDENTIALS.includes(x.credential)) err(id, `credential '${x.credential}' is not one of ${CREDENTIALS.join(", ")}`);
    else if (nightlyRuns(x) && x.credential == null && needsLogin(x)) err(id, `the nightly runs it and it needs a login: say its credential (${CREDENTIALS.join(" or ")}, continuous-integration.md §9.8)`);
    else if (x.credential != null && !nightlyRuns(x) && !x.manual) err(id, `credential '${x.credential}' on an entry no nightly runs`);
    else if (x.credential != null && !needsLogin(x)) err(id, `credential '${x.credential}' on an entry that needs no login: it holds none, and the subscription lane runs it`);
    // …and the credential is the one the entry needs: keys in the api-key
    // lane, the subscription sign-ins (Claude, ChatGPT) in the other, never
    // a key and a sign-in in one guest.
    const needsKey = (x.needs ?? []).some((n) => API_KEY_NEEDS.includes(n));
    if (x.credential === "api-key" && !needsKey) err(id, `credential api-key, but it needs no API key (${API_KEY_NEEDS.join(", ")})`);
    if (x.credential === "subscription" && needsKey) err(id, "it needs an API key, which only credential api-key holds");
    for (const n of SIGN_IN_NEEDS) {
      if (x.credential === "api-key" && (x.needs ?? []).includes(n)) err(id, `it needs ${n}, a subscription sign-in, which the api-key lane never holds`);
    }
    if (typeof x.internet !== "boolean") err(id, "internet must be a boolean");
    if (x.manual != null && (typeof x.manual !== "string" || !x.manual.trim())) err(id, "manual is the reason the entry runs only when named (a non-empty string)");
    // `reported` and `nightly` (test-reorganization.md §6.9): a per-push kind's
    // entry that does not block, with the reason; `nightly` also moves it out
    // of the per-push run into the nightly.
    for (const f of ["reported", "nightly"]) {
      if (x[f] == null) continue;
      if (typeof x[f] !== "string" || !x[f].trim()) err(id, `${f} is the reason the entry does not block (a non-empty string)`);
      if (!PER_PUSH_KINDS.includes(x.kind)) err(id, `${f} applies to a per-push kind's entry (${PER_PUSH_KINDS.join(", ")}); a ${x.kind} entry never blocks anyway`);
      if (x.flaky != null) err(id, `${f} and flaky together: a flaky entry already does not block`);
    }
    if (x.reported != null && x.nightly != null) err(id, "reported and nightly together: a nightly entry is not in the per-push run to be reported there");
    if (x.doc && !existsSync(join(root, x.doc))) err(id, `doc '${x.doc}' does not exist`);
    if (!x.doc) err(id, "doc missing");
    // A kernel-lane entry never runs in the sandbox: its `parallel` says whether it
    // is safe beside the other kernel-lane entries (planPhases).
    if (needsKernel(x) && typeof x.parallel !== "boolean") err(id, "a kernel-lane entry's parallel is true (safe beside the other kernel-lane entries) or false");
    if (needsKernel(x) && !x.frozen && !x.ci) notes.push(`${id}: kernel-lane entry without ci expectations`);
    if (x.ci && !(Number.isInteger(x.ci.maxSkip ?? 0) && Number.isInteger(x.ci.minPass ?? 0))) err(id, "ci.maxSkip / ci.minPass must be integers");
    if (x.queueAs != null && !(Number.isFinite(x.queueAs) && x.queueAs >= 0)) err(id, "queueAs must be seconds (>= 0)");
    if (x.shards != null) {
      if (!Array.isArray(x.shards) || x.shards.length < 2) err(id, "shards must be an array of at least two");
      const shardIds = new Set();
      for (const sh of Array.isArray(x.shards) ? x.shards : []) {
        if (!sh || typeof sh.id !== "string" || !/^[A-Za-z0-9_-]{1,40}$/.test(sh.id)) { err(id, `shard id '${sh?.id}' must be [A-Za-z0-9_-], at most 40`); continue; }
        if (shardIds.has(sh.id)) err(id, `duplicate shard '${sh.id}'`);
        shardIds.add(sh.id);
        if (entries.some((y) => y.id === `${x.id}.${sh.id}`)) err(id, `shard '${sh.id}' collides with entry ${x.id}.${sh.id}`);
        if (sh.cmd != null && (!Array.isArray(sh.cmd) || !sh.cmd.length || sh.cmd.some((t) => typeof t !== "string"))) err(id, `shard '${sh.id}': cmd must be a non-empty argv array`);
        if (sh.env && Object.values(sh.env).some((v) => typeof v !== "string")) err(id, `shard '${sh.id}': env values must be strings`);
        if (sh.timeout != null && !(Number.isFinite(sh.timeout) && sh.timeout > 0)) err(id, `shard '${sh.id}': timeout must be positive seconds`);
        if (sh.queueAs != null && !(Number.isFinite(sh.queueAs) && sh.queueAs >= 0)) err(id, `shard '${sh.id}': queueAs must be seconds (>= 0)`);
      }
    }

    // The frozen axis: integrity ON only in the frozen lane, a named canary, or a re-pin todo.
    if (x.axis === "injection" || x.axis === "full") {
      if (x.frozen) { /* its lane */ }
      else if (x.canary) notes.push(`${id}: canary (axis ${x.axis}) in ${x.kind}`);
      else if (typeof x.todo === "string" && /re-pin/i.test(x.todo)) notes.push(`${id}: axis ${x.axis} in ${x.kind} until re-pinned`);
      else err(id, `axis '${x.axis}' switches integrity on outside the frozen lane (kind ${x.kind}; frozen, a canary, or a re-pin todo only)`);
    }
    for (const c of x.canaries ?? []) {
      if (!canaries.has(c)) err(id, `canary '${c}' is not named in protection-modes.md §10.5`);
      if (!existsSync(join(root, c))) err(id, `canary '${c}' does not exist`);
    }

    for (const v of [].concat(x.variantOf ?? [])) if (!entries.some((y) => y.id === v)) err(id, `variantOf '${v}' is no entry`);

    const c = entryClaims(x, root);
    for (const m of c.missing) err(id, m);
    if (x.session != null) for (const m of sessionProblems(x, c, root)) err(id, m);
    for (const f of c.files) claim(fileClaims, f, x.id);
    for (const s of c.scripts) claim(scriptClaims, s, x.id);
  }

  for (const a of aggregates) {
    const s = readPkgScripts(root, a.cwd);
    if (!s || s[a.script] == null) errors.push(`aggregate ${a.cwd}#${a.script}: no such npm script`);
    for (const id of a.entries ?? []) if (!ids.has(id)) errors.push(`aggregate ${a.cwd}#${a.script}: entry '${id}' does not exist`);
    claim(scriptClaims, `${a.cwd}#${a.script}`, `aggregate:${a.script}`);
  }

  for (const f of walkTestFiles(root)) {
    const by = fileClaims.get(f) ?? [];
    if (!by.length) errors.push(`unclaimed test file: ${f}`);
    else if (by.length > 1) errors.push(`test file claimed twice: ${f} (${by.join(", ")})`);
  }
  for (const s of listTestScripts(root)) {
    const by = scriptClaims.get(s) ?? [];
    if (!by.length) errors.push(`unclaimed npm script: ${s}`);
    else if (by.length > 1) errors.push(`npm script claimed twice: ${s} (${by.join(", ")})`);
  }
  for (const [s, by] of scriptClaims) if (by.length > 1 && !s.includes("#test")) errors.push(`npm script claimed twice: ${s} (${by.join(", ")})`);

  // A session class names one entry's runs: two entries minting the same class
  // would make the dashboard's label and repro line ambiguous.
  const byCls = new Map();
  for (const x of entries) {
    const cls = x.session?.cls;
    if (typeof cls !== "string") continue;
    if (byCls.has(cls)) errors.push(`${x.id}: session class '${cls}' is also entry ${byCls.get(cls)}'s`);
    else byCls.set(cls, x.id);
  }

  // Every canary runs automatically (it is the frozen axis's only signal).
  for (const c of canaries) {
    const by = fileClaims.get(c) ?? [];
    const owners = entries.filter((x) => by.includes(x.id));
    if (!owners.length) errors.push(`canary ${c} is claimed by no entry`);
    else if (!owners.some((x) => !x.frozen && PER_PUSH_KINDS.includes(x.kind))) errors.push(`canary ${c} is not in a per-push kind`);
  }

  // A test that reads docs at run time runs in the docs lane (continuous-integration.md §5.5).
  const sweep = docsLaneSweep(entries, root);
  for (const { file, reads } of sweep.unclaimed) {
    errors.push(`docs lane: ${file} reads ${reads.slice(0, 3).join(", ")}${reads.length > 3 ? ", …" : ""} at run time ` +
      "and no docsLane entry runs it: add it to one (tests/suites.mjs, the docs lane), or say why it needs none " +
      "in a `docs-lane-exempt: <reason>` comment");
  }
  if (sweep.exempt.length) notes.push(`docs lane: ${sweep.exempt.length} test file(s) marked docs-lane-exempt (${sweep.exempt.join(", ")})`);
  // A module that reads docs for its caller carries the marker the sweep
  // finds its callers by (fail closed: an unmarked one is an error).
  for (const { module, line, reads } of unmarkedDocsReaders(root)) {
    errors.push(`docs lane: ${module}:${line} reads ${reads.slice(0, 3).join(", ")}${reads.length > 3 ? ", …" : ""} at run time ` +
      "and declares no `docs-reader:` marker: name the functions or routes a test reaches it by in one " +
      "(a `// docs-reader: \\`name\\`` comment), so the sweep finds those tests, or say why none does in a " +
      "`docs-lane-exempt: <reason>` comment");
  }
  return { errors, notes };
}

// ── coverage by property (test-reorganization.md §5.2) ─────────────────────────

/** The per-push kinds above unit: a property one of them proves runs its real path every push. */
export const COVERAGE_KINDS = ["component", "stack", "replay-drill", "sandbox"];

/**
 * The property × kind table of the entries' `proves` (frozen entries left out:
 * they run only when integrity is revived). Returns { rows: [{ property,
 * byKind: { kind: [ids] }, status }] } where status is `ok` (a suite above unit
 * that really runs every push proves it: runsEveryPush), `warn` (only unit,
 * nightly, or per-push-kind suites that do not run every push do) or `none`.
 * The check FAILS on a `warn` or `none` row (`coverageProblems`): until
 * 2026-10-01 it noted them, while `network-egress/dns` was the one gap (a
 * suite for it found an open hole and waited for the fix; test-reorganization
 * .md §11.1). Every property now has a per-push suite above unit, so a gap is
 * a regression of the manifest, not a known state.
 */
export function coverage(entries) {
  const rows = PROPERTIES.map((property) => {
    const byKind = {};
    let ok = false;
    for (const x of entries) {
      if (x.frozen || !(x.proves ?? []).includes(property)) continue;
      (byKind[x.kind] ??= []).push(x.id);
      if (COVERAGE_KINDS.includes(x.kind) && runsEveryPush(x)) ok = true;
    }
    const status = ok ? "ok" : Object.keys(byKind).length ? "warn" : "none";
    return { property, byKind, status };
  });
  return { rows };
}

/** The check's errors for the properties no per-push suite above unit proves
 *  (`coverage` rows that are not `ok`), one per property. */
export function coverageProblems(entries) {
  return coverage(entries).rows
    .filter((row) => row.status !== "ok")
    .map((row) => `coverage: ${row.property} is ${row.status.toUpperCase()}: no per-push suite above unit proves it` +
      `${Object.keys(row.byKind).length ? ` (only ${Object.entries(row.byKind).map(([k, ids]) => `${k}: ${ids.join(", ")}`).join("; ")})` : ""}` +
      "; claim it in PROVES from a suite that drives the real path (`node scripts/suites.mjs coverage`, test-reorganization.md §5.2)");
}

/** Does the entry run on every push? A per-push kind, outside the frozen lane, and
 *  not kept out of a kind run (manual, internet, flaky, idOnly). */
export function runsEveryPush(x) {
  return PER_PUSH_KINDS.includes(x.kind) && !x.frozen && !x.manual && !x.internet && !nonBlocking(x) && x.idOnly !== true;
}

/** The coverage table as text: a row per property, a column per kind, the suite count in each cell. */
export function renderCoverage(entries) {
  const { rows } = coverage(entries);
  const kinds = KINDS.filter((k) => k !== "install");
  const w = Math.max(...PROPERTIES.map((p) => p.length), 8);
  const head = `${"property".padEnd(w)}  ${kinds.map((k) => k.padStart(13)).join("")}  status`;
  const lines = [head];
  for (const r of rows) {
    lines.push(`${r.property.padEnd(w)}  ${kinds.map((k) => String(r.byKind[k]?.length ?? "·").padStart(13)).join("")}  ${r.status.toUpperCase()}`);
  }
  return lines.join("\n");
}

/** The `session` keys: the e2e test-session class an entry's runs mint (the dashboard reads it). */
export const SESSION_KEYS = ["cls", "file", "label"];
export const SESSION_CLASS_RE = /^[a-z0-9]+(-[a-z0-9]+)*-e2e$/;

/**
 * Problems with an entry's `session: { cls, file, label }`: `cls` is a
 * `<name>-e2e` session class, `file` a path relative to the entry's cwd that
 * exists and that the entry claims (a variant, which claims no files, only
 * needs it to exist), `label` a non-empty string, and no other key.
 */
export function sessionProblems(x, claims = entryClaims(x), root = REPO_ROOT) {
  const s = x.session;
  if (!s || typeof s !== "object" || Array.isArray(s)) return ["session must be an object { cls, file, label }"];
  const out = [];
  for (const k of Object.keys(s)) if (!SESSION_KEYS.includes(k)) out.push(`session has an unknown key '${k}' (${SESSION_KEYS.join(", ")} only)`);
  if (typeof s.cls !== "string" || !SESSION_CLASS_RE.test(s.cls)) out.push(`session.cls '${s.cls}' must match ${SESSION_CLASS_RE}`);
  if (typeof s.label !== "string" || !s.label.trim()) out.push("session.label must be a non-empty string");
  if (typeof s.file !== "string" || !s.file) out.push("session.file must be a path relative to the entry's cwd");
  else {
    const rel = toPosix(relative(root, resolve(root, x.cwd ?? ".", s.file)));
    if (!existsSync(join(root, rel))) out.push(`session.file '${s.file}' does not exist`);
    else if (!x.variantOf && !claims.files.has(rel)) out.push(`session.file '${s.file}' is not a file this entry claims`);
  }
  return out;
}

// ── the generated table: docs/testing/suites.md ────────────────────────────────

export const SUITES_DOC = "docs/testing/suites.md";

/** One line per kind (test-reorganization.md §3), plus the frozen lane. */
export const KIND_NOTES = {
  unit: "One function or module; every push and MR, blocking.",
  component: "One Mandu package through its real interface (its socket, HTTP server or CLI), the rest mocked; every push and MR, blocking.",
  stack: "Several Mandu packages wired as in production, no agent, a scripted model; every push and MR, blocking.",
  "replay-drill": "A real agent CLI and real Mandu against a scripted model; every push and MR, blocking.",
  sandbox: "The real sandbox with no agent: one kernel mechanism, or the real launcher running a scripted command (the kernel lane); every push and MR, blocking.",
  "live-drill": "A real agent CLI with a real model; nightly, reported.",
  env: "The host decides the result (a local model server, a login, the internet, a newly released CLI); nightly, reported.",
  eval: "A Mandu feature's model output scored against a bar; nightly or by hand, reported.",
  install: "A real install in a disposable VM (/dev/kvm and the network); on a release tag and by hand.",
  frozen: "The integrity lane (protection-modes.md), entries of any kind: runs only when the integrity axis is revived.",
};

/** A single-line table cell: whitespace collapsed, `|` escaped. */
const cell = (v) => String(v).replace(/\s+/g, " ").replace(/\|/g, "\\|").trim();
/** An inline code span that survives a backtick in its text. */
const codeSpan = (v) => { const t = cell(v); return t.includes("`") ? `\`\` ${t} \`\`` : `\`${t}\``; };
const DOC_CMD_MAX = 100;

/**
 * The markdown of docs/testing/suites.md for `entries` (pass the PUBLIC manifest). Pure and deterministic.
 * Every line depends on one entry only (no counts; rows sorted by id, not manifest order), so two
 * branches that each add, drop or change different entries merge to exactly this function's output
 * for the merged manifest (test-organization.md §9.2): a generated page must not turn master red.
 */
export function renderSuitesDoc(entries) {
  const L = [
    "# Test suites",
    "",
    "<!-- GENERATED by `node scripts/suites.mjs doc` from tests/suites.mjs. Do not edit by hand. -->",
    "",
    "Every test suite of the public tree, by kind, as the suite manifest `tests/suites.mjs` lists",
    "it ([test-organization.md §5](../design/testing/test-organization.md)). This page is generated: edit",
    "the manifest, then run `node scripts/suites.mjs doc`; `node scripts/suites.mjs check` fails",
    "while the page is stale. Run entries with `scripts/test-all.sh --kind <k>` or",
    "`node scripts/run-suites.mjs --only <id>`; [running-tests.md](running-tests.md) is the guide",
    "(the nightly lanes on your machine, one agent or drill scenario, what CI runs).",
    "",
    "Rows are sorted by id within each kind; the frozen lane is its own section. The page carries no counts (`node scripts/suites.mjs",
    "check` prints them), so two changes that each add an entry merge cleanly and the merged page",
    "is still the generator's output ([test-organization.md §9.2](../design/testing/test-organization.md)).",
    "",
    "Flags: `flaky` runs at its kind's cadence and never blocks; `manual` never runs with its kind,",
    "only when named (a maintainer's batch; the manifest says why); `internet` reaches the public",
    "internet and runs only when named or with `--include-internet`; `serial` runs alone;",
    "`sandbox` runs beside other entries only inside the per-entry sandbox; `todo` has open work",
    "(the manifest says what); `gate` is the opt-in variable the entry sets; `credential` is the",
    "login a nightly entry holds, which picks the nightly job that runs it (`subscription`: the Claude",
    "and ChatGPT sign-ins; `api-key`: vendor API keys; [continuous-integration.md §9.8](../design/testing/continuous-integration.md)).",
    "`kind` (in the frozen section) is the entry's kind. `session` is the test-session class the",
    "entry's runs mint (the dashboard's Testing section). `proves` lists the properties the suite",
    "proves (`PROPERTIES` in scripts/suites.mjs; `node scripts/suites.mjs coverage` tabulates them); a nightly entry that proves",
    "none says why (`none: …`).",
  ];
  for (const t of [...KINDS, "frozen"]) {
    const xs = entries.filter((x) => (t === "frozen" ? x.frozen === true : x.kind === t && !x.frozen))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    // Every kind keeps its heading and table even when empty, so a branch adding a kind's first
    // entry does not insert a heading another branch also inserts.
    L.push("", `## ${t}`, "", KIND_NOTES[t] ?? "", "",
      "| id | axis | cwd | command | needs | flags | proves | session | doc |",
      "|---|---|---|---|---|---|---|---|---|");
    for (const x of xs) {
      let cmd = (x.cmd ?? []).join(" ").replace(/\s+/g, " ");
      if (cmd.length > DOC_CMD_MAX) cmd = `${cmd.slice(0, DOC_CMD_MAX - 1)}…`;
      const shards = Array.isArray(x.shards) && x.shards.length ? ` (${x.shards.length} shards)` : "";
      const flags = [
        t === "frozen" ? `kind ${x.kind}` : "",
        x.flaky ? "flaky" : "", x.manual ? "manual" : "", x.internet ? "internet" : "", x.parallel === false ? "serial" : "",
        x.parallel === "sandbox" ? "sandbox" : "", x.todo ? "todo" : "", x.gate ? `gate ${codeSpan(x.gate)}` : "",
        x.credential ? `credential ${x.credential}` : "",
      ].filter(Boolean).join(", ");
      const doc = x.doc ? `[${cell(x.doc.replace(/^docs\//, ""))}](${toPosix(relative("docs/testing", x.doc))})` : "";
      L.push(`| ${codeSpan(x.id)} | ${cell(x.axis)} | ${codeSpan(x.cwd ?? ".")} | ${codeSpan(cmd)}${shards} | ` +
        `${cell((x.needs ?? []).join(", "))} | ${flags} | ${cell(x.provesNone ? `none: ${x.provesNone}` : (x.proves ?? []).join(", "))} | ${x.session?.cls ? codeSpan(x.session.cls) : ""} | ${doc} |`);
    }
  }
  L.push("");
  return L.join("\n");
}

/** null when docs/testing/suites.md matches the public manifest, else what is wrong. */
export function suitesDocProblem(publicEntries, root = REPO_ROOT) {
  const p = join(root, SUITES_DOC);
  if (!existsSync(p)) return `${SUITES_DOC} is missing: run node scripts/suites.mjs doc`;
  return readFileSync(p, "utf8") === renderSuitesDoc(publicEntries) ? null : `${SUITES_DOC} is stale: run node scripts/suites.mjs doc`;
}

// ── CLI ────────────────────────────────────────────────────────────────────────

// Each command's flags (node:util parseArgs, strict): an unknown flag, a stray
// positional or a missing value is a usage error (exit 2), never ignored, so a
// caller with a typo or a retired flag cannot silently get every entry
// (test-reorganization.md §11.4). `run` and `costs` read their own positionals.
const BOOL = { type: "boolean" };
const STR = { type: "string" };
export const COMMAND_FLAGS = {
  list: {
    kind: STR, frozen: BOOL, platform: STR, only: STR, json: BOOL, ids: BOOL,
    "include-flaky": BOOL, "include-internet": BOOL, "needs-within": STR,
    unsharded: BOOL, public: BOOL, "native-bins": BOOL,
    lane: STR, need: STR, agents: STR, drills: STR,
  },
  packages: { kind: STR, public: BOOL },
  check: { json: BOOL, public: BOOL },
  coverage: { json: BOOL, public: BOOL },
  doc: { check: BOOL },
};
// The retired selection flags (test-reorganization.md §4) get their own message.
const RETIRED_FLAGS = { tier: "--tier is now --kind", "flaky-tiers": "--flaky-tiers is now --flaky-kinds (run-suites.mjs)" };

/** The flags of `cmd`'s argv as an object, or { error } for a usage error. */
export function parseFlags(cmd, argv) {
  for (const a of argv) {
    if (a === "--") break;
    const k = a.startsWith("--") ? a.slice(2).split("=", 1)[0] : null;
    if (k && Object.hasOwn(RETIRED_FLAGS, k)) return { error: `${RETIRED_FLAGS[k]} (test-reorganization.md §4)` };
  }
  try {
    return { ...parseArgs({ args: argv, options: COMMAND_FLAGS[cmd], allowPositionals: false, strict: true }).values };
  } catch (e) {
    return { error: e.message };
  }
}

const USAGE = `usage: node scripts/suites.mjs list [--kind a,b] [--frozen] [--platform linux|darwin] [--only ids] [--json | --ids]
                                    [--include-flaky] [--include-internet] [--needs-within offline|n,n]
                                    [--unsharded] [--public] [--native-bins]
                                    [--lane ${CREDENTIALS.join("|")}] [--need n] [--agents a,b] [--drills id,id]
       node scripts/suites.mjs packages [--kind a,b] [--public]
       node scripts/suites.mjs check [--json] [--public]
       node scripts/suites.mjs coverage [--json] [--public]  (the property x kind table of \`proves\`)
       node scripts/suites.mjs doc [--check]          (writes ${SUITES_DOC} from the public manifest)
       node scripts/suites.mjs costs [--private | --all] [--last N] <summary.json | runs dir>...
                                    (prints the public entries' cost table, > ${COSTS_FILE}:
                                    one summary, that run's durations; a runs directory or
                                    several, each entry's median over the last N (${COSTS_LAST_RUNS})
                                    green full runs; --private: private/suites.mjs's,
                                    > ${PRIVATE_COSTS_FILE}; --all: every entry, no manifest read)
       node scripts/suites.mjs run <id> [-- args…]    (one entry's cmd, cwd and env, output streamed; its exit code)`;

/**
 * Run one entry as the manifest declares it (its cmd in its cwd, the caller's
 * environment plus the entry's env, extra args appended), output streamed.
 * The npm scripts of the claude-e2e cuts are `suites.mjs run <id>`, so the
 * scenario lists live in the manifest only (test-organization.md §9 step 2).
 * MANDU_SUITES_RUN names the entry being run: an entry whose cmd leads back
 * to `run` of itself is refused instead of looping. Returns the exit code.
 */
export function runEntry(x, { root = REPO_ROOT, args = [], stdio = "inherit", env = process.env } = {}) {
  if (env.MANDU_SUITES_RUN === x.id) {
    process.stderr.write(`suites: ${x.id} runs itself (its cmd leads back to \`suites.mjs run ${x.id}\`)\n`);
    return 2;
  }
  const [bin, ...rest] = x.cmd;
  const r = spawnSync(bin, [...rest, ...args], {
    cwd: join(root, x.cwd ?? "."), stdio, env: { ...env, ...(x.env ?? {}), MANDU_SUITES_RUN: x.id },
  });
  if (r.error) { process.stderr.write(`suites: ${x.id}: ${r.error.message}\n`); return 127; }
  if (r.signal) return 128 + (osConstants.signals[r.signal] ?? 0);
  return r.status ?? 1;
}

export async function main(argv = process.argv.slice(2), { root = REPO_ROOT, stdout = process.stdout } = {}) {
  const [cmd, ...rest] = argv;
  const say = (s) => stdout.write(`${s}\n`);
  const usageError = (why) => { process.stderr.write(`${why ? `suites: ${why}\n` : ""}${USAGE}\n`); return 2; };
  if (cmd === "costs") {
    let priv = false, every = false, last = null;
    const args = [];
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      if (a === "--private") priv = true;
      else if (a === "--all") every = true;
      else if (a === "--last") {
        last = Number(rest[++i]);
        if (!(Number.isInteger(last) && last >= 1)) return usageError("costs --last: a number of runs (>= 1)");
      } else if (a.startsWith("-")) return usageError(`unknown option '${a}'`);
      else args.push(a);
    }
    if (!args.length) return usageError(null);
    if (priv && every) return usageError("costs: --private or --all, not both");
    // Each table names only its own manifest's entries (shards included), so
    // the public one never names an entry the public snapshot lacks. --all
    // names every entry that ran (vm-run.sh's measured table for the guest),
    // without reading the manifest.
    let keep = () => true;
    if (!every) {
      const { entries: all, privateLoaded } = await loadManifest({ root });
      if (priv && !privateLoaded) { process.stderr.write("suites: costs --private: no private/suites.mjs in this tree\n"); return 2; }
      const ids = new Set(expandShards(all).filter((x) => !!x.private === priv).map((x) => x.id));
      keep = (id) => ids.has(id);
    }
    let table;
    try {
      // One summary file: that run's table, as it ran. A runs directory or
      // several summaries: the median of the recent green full runs.
      table = args.length === 1 && last == null && !statSync(args[0]).isDirectory()
        ? costsFromSummary(JSON.parse(readFileSync(args[0], "utf8")), keep)
        : costsFromRuns(readSummaries(args), { last: last ?? COSTS_LAST_RUNS, keep });
    } catch (e) { process.stderr.write(`suites: costs: ${e.message}\n`); return 2; }
    say(JSON.stringify(table, null, 2));
    return 0;
  }
  if (cmd === "run") {
    const dash = argv.indexOf("--");
    const id = argv[1];
    if (!id || id.startsWith("-") || (dash !== -1 && dash < 2)) return usageError(null);
    // Anything between the id and `--` is refused: the entry's own arguments go after `--`.
    const stray = argv.slice(2, dash === -1 ? argv.length : dash);
    if (stray.length) return usageError(`run ${id}: unexpected '${stray.join(" ")}' (the entry's arguments go after --)`);
    const { entries: all } = await loadManifest({ root });
    const x = all.find((y) => y.id === id) ?? all.find((y) => (y.aliases ?? []).includes(id));
    if (!x) { process.stderr.write(`suites: no entry '${id}'\n`); return 2; }
    return runEntry(x, { root, args: dash === -1 ? [] : argv.slice(dash + 1) });
  }
  if (!Object.hasOwn(COMMAND_FLAGS, cmd ?? "")) return usageError(cmd == null ? null : `unknown command '${cmd}'`);
  const f = parseFlags(cmd, rest);
  if (f.error) return usageError(f.error);
  if (cmd === "doc") {
    const { entries: pub } = await loadManifest({ root, includePrivate: false });
    if (f.check) {
      const problem = suitesDocProblem(pub, root);
      if (problem) { process.stderr.write(`suites: ${problem}\n`); return 1; }
      say(`${SUITES_DOC} is up to date`);
      return 0;
    }
    writeFileSync(join(root, SUITES_DOC), renderSuitesDoc(pub));
    say(`wrote ${SUITES_DOC} (${pub.length} entries)`);
    return 0;
  }
  const { entries, aggregates, privateProblems } = await loadManifest({ root, includePrivate: !f.public });
  if (cmd === "list") {
    // No --kind and no --frozen: every entry (every kind and the frozen lane).
    const all = !f.kind && !f.frozen && !f.drills;
    const kinds = f.kind ? splitList(f.kind) : all ? KINDS : [];
    for (const k of kinds) if (!KINDS.includes(k)) { process.stderr.write(`suites: unknown kind '${k}' (${KINDS.join(", ")})\n`); return 2; }
    if (f.lane != null && !CREDENTIALS.includes(f.lane)) { process.stderr.write(`suites: --lane is ${CREDENTIALS.join(" or ")}\n`); return 2; }
    const { selected, unknown } = selectEntries(entries, {
      kinds, frozen: all || Boolean(f.frozen), only: splitList(f.only), platform: f.platform ?? null,
      includeFlaky: f["include-flaky"] || all, includeInternet: f["include-internet"] || all,
      unsharded: Boolean(f.unsharded), lane: f.lane ?? null, need: f.need ?? null,
      agents: f.agents ? splitList(f.agents) : null, drills: f.drills ? splitList(f.drills) : null,
    });
    if (unknown.length) { process.stderr.write(`suites: no entry matches ${unknown.join(", ")}\n`); return 2; }
    let out = selected;
    // --needs-within offline|<n,n>: only entries whose needs all fall inside the set
    // (test-all.sh --integrity uses it to add the frozen lane's offline-runnable part).
    // --native-bins: only entries that run the native bins (usesNativeBins);
    // test-all.sh builds them first when this is non-empty.
    if (f["native-bins"]) out = out.filter(usesNativeBins);
    if (f["needs-within"]) {
      const within = f["needs-within"] === "offline" ? OFFLINE_NEEDS : new Set(splitList(f["needs-within"]));
      out = out.filter((x) => (x.needs ?? []).every((n) => within.has(n)));
    }
    if (f.ids) { say(out.map((x) => x.id).join(",")); return 0; }
    if (f.json) { say(JSON.stringify(out, null, 2)); return 0; }
    const selected2 = out;
    const w = Math.max(...selected2.map((x) => x.id.length), 4);
    for (const x of selected2) {
      const flags = [x.flaky ? "flaky" : "", x.internet ? "internet" : "", x.parallel === false ? "serial" : "", x.todo ? "todo" : ""].filter(Boolean).join(",");
      say(`${x.id.padEnd(w)}  ${x.kind.padEnd(12)} ${x.axis.padEnd(9)} ${x.cwd.padEnd(30)} ${x.frozen ? "frozen" : ""}${x.frozen && flags ? "," : ""}${flags}`);
    }
    return 0;
  }
  if (cmd === "packages") {
    const kinds = f.kind ? splitList(f.kind) : null;
    for (const k of kinds ?? []) if (!KINDS.includes(k)) { process.stderr.write(`suites: unknown kind '${k}'\n`); return 2; }
    for (const d of packageDirs(kinds ? entries.filter((x) => kinds.includes(x.kind) && !x.frozen) : entries, root)) say(d);
    return 0;
  }
  if (cmd === "coverage") {
    if (f.json) { say(JSON.stringify(coverage(entries), null, 2)); return 0; }
    say(renderCoverage(entries));
    return 0;
  }
  if (cmd === "check") {
    const m = checkManifest(entries, aggregates, root);
    // The private manifest's own problems (the drill catalog's index and scripts, test-reorganization.md §6.8).
    const drill = privateProblems ? await privateProblems(root) : [];
    // The generated table (docs/testing/suites.md) is part of the check, so it cannot drift.
    const { entries: pub } = await loadManifest({ root, includePrivate: false });
    const docProblem = suitesDocProblem(pub, root);
    const r = { ...m, errors: [...m.errors, ...drill.map((e) => `drill: ${e}`), ...(docProblem ? [`doc: ${docProblem}`] : []), ...coverageProblems(entries)] };
    if (f.json) { say(JSON.stringify({ ...r, drill }, null, 2)); return r.errors.length ? 1 : 0; }
    for (const n of r.notes) say(`note: ${n}`);
    for (const e of r.errors) say(`ERROR: ${e}`);
    const counts = [...KINDS.map((k) => `${k} ${entries.filter((x) => x.kind === k && !x.frozen).length}`), `frozen ${entries.filter((x) => x.frozen).length}`].join(", ");
    say(`${entries.length} entries (${counts}); ${r.errors.length} error(s)`);
    return r.errors.length ? 1 : 0;
  }
  process.stderr.write(`${USAGE}\n`);
  return 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().then((rc) => { process.exitCode = rc; }, (e) => { process.stderr.write(`suites: ${e?.stack ?? e}\n`); process.exitCode = 2; });
}
