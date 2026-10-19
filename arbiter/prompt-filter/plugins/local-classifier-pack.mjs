#!/usr/bin/env node
/**
 * local-classifier-pack — writes the pack that installs Mandu's reference
 * classifier plugin (local-classifier.mjs; confidentiality-plan-15 §4.3,
 * §13.5). Mandu-new.
 *
 *   node arbiter/prompt-filter/plugins/local-classifier-pack.mjs \
 *       [--id local-classifier] [--categories pii.person,pii.contact,…] \
 *       [--deadline-ms 30000] [--node /usr/bin/node] > ~/.mandu/prompt-filters/local-classifier.yaml
 *
 * The pack pins the node binary and the classifier script by path and
 * SHA-256 (computed here, from the files as they are now), declares the
 * categories the classifier may report (each `no-model` when masked) and
 * asks for a model (`endpoint: required`). It does nothing until the policy
 * turns it on and names a `local: true` model:
 *
 *   prompt_filters:
 *     filters:
 *       local-classifier: { on: true, endpoint: <your local model's name> }
 *
 * Re-run it after upgrading node or Mandu: a pin that no longer matches
 * blocks the prompt (the filter's `on_error`).
 */
import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const DEFAULT_CATEGORIES = ["pii.person", "pii.contact", "pii.id-number", "pii.financial", "pii.health", "org.confidential"];

const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");

/** The pack's YAML. Pure over its inputs. */
export function packYaml({ id = "local-classifier", node, nodeSha, script, scriptSha, categories = DEFAULT_CATEGORIES, deadlineMs = 30000 }) {
  return [
    "# Mandu's reference classifier plugin (docs/design/confidentiality/confidentiality-plan-15-prompt-filter.md §4.3, §13.5).",
    "# Turn it on in policy.yaml with a local: true model:",
    "#   prompt_filters:",
    "#     filters:",
    `#       ${id}: { on: true, endpoint: <your local model's name> }`,
    `pack: ${id}`,
    "version: 1",
    "description: a local model classifies each new prompt (and the text the harness adds) before it leaves the machine",
    "plugin:",
    `  exec: ${node}`,
    `  sha256: "${nodeSha}"`,
    `  script: ${script}`,
    `  script_sha256: "${scriptSha}"`,
    "  cost: model",
    "  endpoint: required",
    `  deadline_ms: ${deadlineMs}`,
    "categories:",
    ...categories.map((c) => `  - { category: ${c}, level: no-model }`),
    "",
  ].join("\n");
}

function main(argv) {
  const arg = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  const node = realpathSync(arg("--node") ?? process.execPath);
  const script = realpathSync(join(dirname(fileURLToPath(import.meta.url)), "local-classifier.mjs"));
  const categories = (arg("--categories") ?? DEFAULT_CATEGORIES.join(",")).split(",").map((s) => s.trim()).filter(Boolean);
  const deadlineMs = Number(arg("--deadline-ms") ?? 30000);
  process.stdout.write(packYaml({ id: arg("--id") ?? "local-classifier", node, nodeSha: sha(node), script, scriptSha: sha(script), categories, deadlineMs }));
}

if (process.argv[1]?.endsWith("/local-classifier-pack.mjs")) main(process.argv.slice(2));
