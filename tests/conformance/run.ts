/**
 * run — the Mandu conformance scenario runner.
 *
 * Loads every scenarios/*.yaml (js-yaml), boots a offline real-component stack
 * per scenario (buildStack), evaluates the scenario's declarative assertions
 * (evaluate), and prints adfi-style per-scenario ✓/✗ output + a final summary.
 * Exits non-zero on any failure. DETERMINISTIC: no API key, no network — the
 * ingress proxies forward to a mock upstream and the U-LLM is mocked.
 *
 * Mirrors adfi-openclaw's e2e runner shape (load YAML scenarios → evaluate the
 * assertion DSL against the system under test → report), adapted to drive the
 * Mandu components instead of an OpenClaw agent subprocess.
 */

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as yaml from "js-yaml";

import { buildStack, header, record, printSummaryAndExit } from "./lib/harness.js";
import { evaluate, type Scenario } from "./lib/assertions.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCENARIO_DIR = join(__dirname, "scenarios");

function loadScenarios(): Scenario[] {
  const files = readdirSync(SCENARIO_DIR)
    .filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"))
    .sort();
  const scenarios: Scenario[] = [];
  for (const f of files) {
    const doc = yaml.load(readFileSync(join(SCENARIO_DIR, f), "utf-8")) as Scenario;
    if (!doc || typeof doc !== "object") throw new Error(`${f}: not a scenario object`);
    if (!doc.id || !doc.target || !Array.isArray(doc.assertions)) {
      throw new Error(`${f}: missing required fields (id / target / assertions)`);
    }
    scenarios.push(doc);
  }
  return scenarios;
}

async function main(): Promise<void> {
  const scenarios = loadScenarios();
  console.log(
    `\n\x1b[1mMandu conformance suite\x1b[0m — ${scenarios.length} scenarios ` +
      `(real arbiter + real ingress proxy, mock upstream, no network)\n`,
  );

  for (const scenario of scenarios) {
    const tags = scenario.tags?.length ? ` \x1b[2m[${scenario.tags.join(", ")}]\x1b[0m` : "";
    header(`${scenario.id} · ${scenario.name}${tags}`);

    const stack = await buildStack({ target: scenario.target, sessionId: `${scenario.id}-session` });
    try {
      const results = await evaluate(scenario, stack);
      for (const r of results) record(r.label, r.passed, r.reason);
    } catch (err) {
      record(`${scenario.id}: scenario crashed`, false, (err as Error).message);
    } finally {
      await stack.dispose();
    }
  }

  printSummaryAndExit();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
