/**
 * agent-registry — ONE list of agents (scripts/agents/agent-registry.mjs;
 * docs/design/agents/supported-agents.md §5.7):
 *
 *   - the table is sound and its typed copies (its declarations, the
 *     dashboard's, the launcher's and the arbiter's copies) are fresh, and
 *     the lists the launcher and the arbiter build on them are the
 *     registry's agents plus `shell`;
 *   - the launcher's tested-version table has a range for every agent and a
 *     generation for every later line, under the registry's names;
 *   - the plain-JS tables that must name every line do (the manifest's
 *     `needs` vocabulary), and every line's pin is in pins.env;
 *   - the public tree's scripts, tests, dashboard, launcher and arbiter
 *     hold no hand-copied agent list (tests/lib/agent-lists.ts: four or more agent ids in one
 *     list, row array or plain-JS keyed table): each is the registry or a
 *     named filter over it. The drill suite holds its own tree to the same
 *     rule.
 *
 * Pure: reads source files, starts nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  AGENTS, AGENT_LINES, AGENT_NAMES, API_KEY_AGENTS, CACHED_LINES, LINES, NPM_AGENTS, PIN_KEYS, agentOfLine, tableProblems,
} from "../../scripts/agents/agent-registry.mjs";
import { TESTED_AGENT_GENERATIONS, TESTED_AGENT_VERSIONS } from "../../launcher/src/agent-versions.js";
import { AGENTS as LAUNCHER_AGENTS, LINES as LAUNCHER_LINES } from "../../launcher/src/generated/agents.js";
import { TARGETS } from "../../launcher/src/types.js";
import { AGENTS as ARBITER_AGENTS } from "../../arbiter/src/generated/agents.js";
import { AGENT_STORES, KNOWN_TARGETS } from "../../arbiter/policy/secret-discovery.js";
import { AGENT_KINDS } from "../../dashboard/src/event-source/registry.js";
import { findAgentLists, idsNamed, sliceFrom, sourceFiles, type FoundList } from "../lib/agent-lists.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // pure: source text only; no arbiter is started

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const COPIES = join(REPO, "scripts", "agents", "agent-copies.mjs");

test("the table is sound: ids, a generation's agent, wire, credential and sign-in, pin", () => {
  assert.deepEqual(tableProblems(), []);
  assert.ok(AGENTS.length > 0 && AGENTS.every((a) => LINES.includes(a)));
  for (const l of AGENT_LINES) assert.ok(AGENTS.includes(agentOfLine(l.id) as (typeof AGENTS)[number]), l.id);
  // the soundness check refuses what it should
  const broken = [...AGENT_LINES, { ...AGENT_LINES[0]!, id: "claude" }, { ...AGENT_LINES[0]!, id: "x2", agent: "nope", generation: 2 }] as unknown as typeof AGENT_LINES;
  const problems = tableProblems(broken);
  assert.ok(problems.some((p) => p.startsWith("claude: listed twice")), problems.join("; "));
  assert.ok(problems.some((p) => p.startsWith("x2: its agent nope")), problems.join("; "));
});

test("the named filters are the rows' fields", () => {
  assert.deepEqual([...API_KEY_AGENTS], AGENTS.filter((a) => AGENT_LINES.find((l) => l.id === a)!.credential === "api-key"));
  assert.deepEqual([...CACHED_LINES], AGENT_LINES.filter((l) => l.cache).map((l) => l.id));
  for (const a of AGENTS) assert.equal(AGENT_NAMES[a], AGENT_LINES.find((l) => l.id === a)!.name);
  assert.deepEqual([...NPM_AGENTS], AGENTS.filter((a) => AGENT_LINES.find((l) => l.id === a)!.npm !== undefined));
});

test("the typed copies match the table (run `node scripts/agents/agent-copies.mjs generate`)", async () => {
  const m = (await import(pathToFileURL(COPIES).href)) as { staleCopies: (root?: string) => string[] };
  assert.deepEqual(m.staleCopies(), []);
  const r = spawnSync(process.execPath, [COPIES, "check"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual([...AGENT_KINDS], [...AGENTS], "the dashboard's agent kinds are the registry's agents");
  assert.deepEqual([...LAUNCHER_AGENTS], [...AGENTS], "the launcher's copy");
  assert.deepEqual([...LAUNCHER_LINES], [...LINES], "the launcher's copy of the lines");
  assert.deepEqual([...ARBITER_AGENTS], [...AGENTS], "the arbiter's copy");
});

test("the launcher's targets and the arbiter's known targets are the registry's agents and `shell`; the raw stores a named subset", () => {
  assert.deepEqual([...TARGETS], [...AGENTS, "shell"], "launcher/src/types.ts TARGETS (--target, doctor --secrets --target)");
  assert.deepEqual([...KNOWN_TARGETS], [...AGENTS, "shell"], "arbiter secret-discovery.ts KNOWN_TARGETS (keptLoginOwners)");
  // StoreOwner is every agent but OpenClaw (secret-discovery.ts): a store
  // left raw is never masked, so the subset is named, not the agent list.
  assert.deepEqual(Object.keys(AGENT_STORES), AGENTS.filter((a) => a !== "openclaw"));
});

test("the launcher's tested-version table: a range for every agent, a generation for every later line, the registry's names", () => {
  assert.deepEqual(Object.keys(TESTED_AGENT_VERSIONS), [...AGENTS]);
  for (const a of AGENTS) assert.equal(TESTED_AGENT_VERSIONS[a].name, AGENT_NAMES[a], a);
  const generations = Object.entries(TESTED_AGENT_GENERATIONS).flatMap(([a, gs]) => (gs ?? []).map((g) => `${a}@${g.major}`)).sort();
  const lines = AGENT_LINES.filter((l) => l.generation !== undefined).map((l) => `${l.agent}@${l.generation}`).sort();
  assert.deepEqual(generations, lines, "each later line of the registry is a tested generation, and each tested generation a line");
});

test("every line's pin is in pins.env, and the manifest's needs vocabulary names every line and sign-in", async () => {
  const pins = readFileSync(join(REPO, "scripts", "ci", "pins.env"), "utf8");
  for (const l of LINES) assert.match(pins, new RegExp(`^${PIN_KEYS[l]}=`, "m"), `${l}: ${PIN_KEYS[l]} in scripts/ci/pins.env`);
  const m = (await import(pathToFileURL(join(REPO, "scripts", "suites.mjs")).href)) as {
    NEEDS: Record<string, string>; AGENTS: readonly string[]; LIVE_AGENTS: readonly string[]; AGENT_OF_NEED: Record<string, string>;
  };
  for (const l of AGENT_LINES) {
    assert.ok(m.NEEDS[l.id], `NEEDS names ${l.id}`);
    if (l.signIn) assert.ok(m.NEEDS[l.signIn], `NEEDS names ${l.signIn}`);
    assert.equal(m.AGENT_OF_NEED[l.id], l.agent);
    if (l.signIn) assert.equal(m.AGENT_OF_NEED[l.signIn], l.agent);
  }
  assert.deepEqual([...m.AGENTS], [...AGENTS]);
  assert.deepEqual([...m.LIVE_AGENTS], [...LINES]);
});

test("the list finder: a run, a row array and a plain-JS keyed table of four or more agents; not three", () => {
  const ids = [...LINES];
  const found = (text: string, file = "x.mjs"): FoundList[] => findAgentLists(text, ids, { file });
  assert.equal(found(`const A = ["claude", "codex", "openclaw", "opencode"];`).length, 1);
  assert.equal(found(`type T = "claude" | "codex"\n  | "goose" | "openclaw";`, "x.ts").length, 1);
  assert.equal(found(`f("claude", "shell", "codex", "opencode", "goose")`)[0]!.ids.length, 4, "other words between them");
  assert.equal(found(`const A = ["openclaw", "opencode", "goose"];`).length, 0, "a subset of three is not looked for");
  assert.equal(found(`[{ id: 'claude', n: 1 }, { id: 'codex' },\n { id: 'openclaw' }, { id: 'goose' }]`)[0]!.form, "rows");
  const keyed = `const L = { claude: 'C', codex: 'X', "opencode": 'O', goose: 'G' };`;
  assert.equal(found(keyed)[0]!.form, "keys");
  assert.equal(found(keyed, "x.ts").length, 0, "a TypeScript table is the type checker's");
  assert.equal(found(`// claude: codex: opencode: goose:\nconst s = "claude: codex: opencode: goose:";`).length, 0, "comments and strings are not keys");
  assert.deepEqual(idsNamed(`<option value="claude">…<option value="opencode2">`, ids), ["claude", "opencode2"]);
  assert.equal(sliceFrom(`x const M = { a: { b: 1 } }; y`, "const M"), "const M = { a: { b: 1 } }");
});

/** The lists the public tree may hold: the registry and its generated copies
 *  (held fresh above), and the `needs` vocabulary, which names every line
 *  among the other needs (held above). */
const ALLOWED: ReadonlyArray<{ file: string; form: FoundList["form"]; why: string }> = [
  { file: "scripts/agents/agent-registry.mjs", form: "rows", why: "the registry" },
  { file: "dashboard/src/generated/agents.ts", form: "list", why: "the dashboard's generated copy" },
  { file: "launcher/src/generated/agents.ts", form: "list", why: "the launcher's generated copy" },
  { file: "arbiter/src/generated/agents.ts", form: "list", why: "the arbiter's generated copy" },
  { file: "scripts/suites.mjs", form: "keys", why: "NEEDS: a description per need, every line among them" },
];

/** The tests package's public trees, named one by one: this suite reads no
 *  maintainers' tree, so a change there never selects it (a new public tree
 *  joins this list). */
const PUBLIC_TESTS = ["tests/suites.mjs", "tests/lib", "tests/stack", "tests/sandbox", "tests/env", "tests/integrity", "tests/conformance"];

test("the public tree holds no hand-copied agent list: each is the registry or a named filter over it", () => {
  const files = sourceFiles(REPO, ["scripts", ...PUBLIC_TESTS, "dashboard/src", "dashboard/public", "launcher", "arbiter"]);
  assert.ok(files.length > 100, `the walk found the sources (${files.length})`);
  for (const pkg of ["launcher/src/", "arbiter/policy/"]) assert.ok(files.some((f) => f.startsWith(pkg)), `the walk reads ${pkg}`);
  const seen = new Set<string>();
  const copies: string[] = [];
  for (const f of files) {
    for (const l of findAgentLists(readFileSync(join(REPO, f), "utf8"), LINES, { file: f })) {
      const ok = ALLOWED.find((a) => a.file === f && a.form === l.form);
      if (ok) { seen.add(`${f}:${l.form}`); continue; }
      copies.push(`${f}:${l.line}: ${l.form} of ${l.ids.join(", ")}`);
    }
  }
  assert.deepEqual(copies, [], "import the agents from scripts/agents/agent-registry.mjs (or a named filter over it; a standalone package: a generated copy, scripts/agents/agent-copies.mjs)");
  for (const a of ALLOWED) assert.ok(seen.has(`${a.file}:${a.form}`), `${a.file} (${a.why}) is still where this test allows it`);
  // the allowed tables still name every line
  const needs = sliceFrom(readFileSync(join(REPO, "scripts", "suites.mjs"), "utf8"), "export const NEEDS");
  assert.ok(needs);
  assert.deepEqual(idsNamed(needs, LINES), [...LINES]);
});
