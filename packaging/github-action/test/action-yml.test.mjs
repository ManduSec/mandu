// action.yml against the code it runs: every input reaches run.mjs, no input
// is pasted into a shell script, and the pinned versions are the ones this
// tree ships and was tested with. Read as text: the action ships no YAML
// library. Design: docs/design/distribution/github-action.md §3, §8.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ACTION_DIR = join(HERE, "..");
const REPO = join(ACTION_DIR, "..", "..");
const yml = readFileSync(join(ACTION_DIR, "action.yml"), "utf8");
const inputsSrc = readFileSync(join(ACTION_DIR, "lib", "inputs.mjs"), "utf8");

/** The `inputs:` names and defaults (two-space keys under `inputs:`). */
function inputs() {
  const block = /^inputs:\n([\s\S]*?)^\S/m.exec(yml)?.[1] ?? "";
  const out = new Map();
  let cur = null;
  for (const line of block.split("\n")) {
    const k = /^ {2}([a-z][a-z0-9-]*):\s*$/.exec(line);
    if (k) { cur = k[1]; out.set(cur, null); continue; }
    const d = /^ {4}default:\s*(.*)$/.exec(line);
    if (d && cur) out.set(cur, d[1].replace(/^"(.*)"$/, "$1"));
  }
  return out;
}

const NOT_FOR_RUN = new Set(["mandu-version", "agent-version", "node-version", "anthropic-api-key", "claude-code-oauth-token", "openai-api-key"]);
const envName = (input) => `MANDU_ACTION_${input.toUpperCase().replace(/-/g, "_")}`;

test("every input is mapped to run.mjs's variable, and run.mjs reads no variable without an input", () => {
  const ins = inputs();
  assert.ok(ins.size >= 20, `inputs parsed: ${[...ins.keys()].join(", ")}`);
  for (const name of ins.keys()) {
    if (NOT_FOR_RUN.has(name)) continue;
    assert.match(yml, new RegExp(`^ {8}${envName(name)}: \\$\\{\\{ inputs\\.${name} \\}\\}$`, "m"), `${name} is handed to run.mjs`);
  }
  const read = [...inputsSrc.matchAll(/get\("([A-Z_]+)"\)/g)].map((m) => `MANDU_ACTION_${m[1]}`);
  const mapped = new Set([...ins.keys()].map(envName));
  for (const v of read) assert.ok(mapped.has(v), `${v} has an input`);
});

test("no input is pasted into a shell script (script injection): inputs reach `run:` only through env", () => {
  const runs = [...yml.matchAll(/^ {6}run: \|\n((?: {8}.*\n|\n)+)/gm)].map((m) => m[1]);
  runs.push(...[...yml.matchAll(/^ {6}run: (?!\|)(.*)$/gm)].map((m) => m[1]));
  assert.ok(runs.length >= 2, "both run steps found");
  for (const body of runs) assert.ok(!body.includes("${{"), `no expression inside a run script:\n${body}`);
});

test("the default mandu-version is the version this tree ships (scripts/set-version.sh moves it)", () => {
  const version = JSON.parse(readFileSync(join(REPO, "launcher", "package.json"), "utf8")).version;
  assert.equal(inputs().get("mandu-version"), version);
  assert.match(readFileSync(join(REPO, "scripts", "set-version.sh"), "utf8"), /packaging\/github-action\/action\.yml/);
});

test("the agents installed by default are the newest Mandu tested (launcher/src/agent-versions.ts)", () => {
  const src = readFileSync(join(REPO, "launcher", "src", "agent-versions.ts"), "utf8");
  const max = (agent) => new RegExp(`\\n  ${agent}: \\{[\\s\\S]*?max: "([^"]+)"`).exec(src)?.[1];
  assert.match(yml, new RegExp(`claude\\) pkg="@anthropic-ai/claude-code"; tested="${max("claude").replace(/\./g, "\\.")}"`));
  assert.match(yml, new RegExp(`codex\\)  pkg="@openai/codex"; tested="${max("codex").replace(/\./g, "\\.")}"`));
});

test("setup-node is the same major the repository's own workflows pin", () => {
  const ci = readFileSync(join(REPO, ".github", "workflows", "ci.yml"), "utf8");
  const pin = /uses: (actions\/setup-node@v\d+)/.exec(ci)?.[1];
  assert.ok(pin, "ci.yml pins setup-node");
  assert.ok(yml.includes(`uses: ${pin}`), `action.yml uses ${pin}`);
});

test("the run step runs run.mjs from the action's own directory", () => {
  assert.match(yml, /run: node "\$GITHUB_ACTION_PATH\/run\.mjs"/);
  assert.match(yml, /^ {2}using: composite$/m);
});
