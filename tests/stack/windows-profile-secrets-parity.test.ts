/**
 * windows-profile-secrets-parity — the launcher's Windows-profile probe list
 * (launcher/src/wsl.ts `WINDOWS_PROFILE_SECRET_PATHS`) is the secret
 * catalog's home-anchored stores (arbiter/policy/secret-catalog.ts
 * `SECRET_PREFIXES`) minus the agent-auth paths discovery never twins. The
 * launcher ships standalone, so the list is mirrored; a store added to the
 * catalog and not to the mirror would be twinned under the Linux HOME and
 * left raw under /mnt/c/Users/<name> on WSL (confidentiality.md §7.2).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { WINDOWS_PROFILE_SECRET_PATHS } from "../../launcher/src/wsl.js";
import { SECRET_PREFIXES } from "../../arbiter/policy/secret-catalog.js";
import { isAgentAuthPath } from "../../arbiter/policy/secret-discovery.js";

test("the Windows-profile probe list is the catalog's home stores, agent auth excluded", () => {
  const home = "/h";
  const catalog = SECRET_PREFIXES
    .filter((p) => p.startsWith("~/"))
    .filter((p) => !isAgentAuthPath(`${home}/${p.slice(2)}`, home))
    .map((p) => p.slice(2));
  assert.deepEqual([...WINDOWS_PROFILE_SECRET_PATHS].sort(), [...new Set(catalog)].sort());
});
