/**
 * endpoint-tls-parity.test.ts — ONE connection-time TLS check in five
 * packages (docs/design/confidentiality/model-endpoints.md §2 D3).
 *
 * The helper, both model proxies, `mandu doctor` and the dashboard probe dial
 * a declared endpoint with its `tls:` checks, and ship standalone, so
 * endpoint-tls.ts is copied verbatim into each. A drift would let one door
 * accept a server another refuses; the copies must stay byte-identical.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the checks guard local-model bytes (confidentiality); no axis is read

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const COPIES = [
  "interceptors/inspect-mcp/src/endpoint-tls.ts",
  "interceptors/anthropic-proxy/src/endpoint-tls.ts",
  "interceptors/openai-proxy/src/endpoint-tls.ts",
  "launcher/src/endpoint-tls.ts",
  "dashboard/src/endpoint-tls.ts",
];

test("the five copies of endpoint-tls.ts are byte-identical", () => {
  const master = readFileSync(join(ROOT, COPIES[0]!), "utf8");
  for (const c of COPIES.slice(1)) {
    assert.equal(readFileSync(join(ROOT, c), "utf8"), master, `${c} drifted from ${COPIES[0]}; copy the inspect-mcp file out again`);
  }
});
