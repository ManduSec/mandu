/**
 * Regenerate arbiter/policy/policy-edit.schema.json from policyAgentEditSchema()
 * (the schema a model is offered; policy-surface.md §8.4.3, §8.4.3a). Run: npx tsx scripts/gen-policy-schema.ts
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { policyAgentEditSchema } from "../policy/policy-edit-schema.js";

const out = join(dirname(fileURLToPath(import.meta.url)), "..", "policy", "policy-edit.schema.json");
writeFileSync(out, JSON.stringify(policyAgentEditSchema(), null, 2) + "\n");
console.log(`wrote ${out}`);
