/**
 * about-mandu-parity — Settings › About Mandu's facts are the launcher's
 * (dashboard.md §4.25 *About Mandu*). The dashboard ships standalone and
 * mirrors the launcher's docs base (launcher/src/docs-url.ts) rather than
 * importing it, as it mirrors the tested-version table
 * (agent-versions-parity.test.ts, beside this one in the docs lane). This
 * keeps the mirrors equal, the issue tracker one address, the release the
 * card shows the one every manifest names, and the user guide's
 * Troubleshooting heading where the card's link lands. Pure: no server, no
 * arbiter, nothing enforced, so no axis is in play. Mandu-new.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as dashDocs from "../../dashboard/src/release-version.js";
import * as dashVersions from "../../dashboard/src/agent-versions.js";
import { homeAbout } from "../../dashboard/src/view-model/home.js";
import * as launcherDocs from "../../launcher/src/docs-url.js";
import * as launcherVersions from "../../launcher/src/agent-versions.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const versionOf = (pkg: string): string => (JSON.parse(readFileSync(join(REPO, pkg, "package.json"), "utf8")) as { version: string }).version;

test("the dashboard's docs base is the launcher's, and joins a path the same way", () => {
  assert.equal(dashDocs.DOCS_BASE_URL, launcherDocs.DOCS_BASE_URL);
  for (const p of ["docs/usage.md", "docs/usage.md#troubleshooting", "/docs/x.md", "./docs/y.md"]) {
    assert.equal(dashDocs.docsUrl(p), launcherDocs.docsUrl(p), p);
  }
});

test("Report a problem is the launcher's issue tracker", () => {
  assert.equal(dashVersions.ISSUES_URL, launcherVersions.ISSUES_URL);
  assert.equal(homeAbout("1.0.0").issuesUrl, launcherVersions.ISSUES_URL);
});

test("the release the card shows is the launcher's", () => {
  assert.equal(versionOf("dashboard"), versionOf("launcher"), "one release in both manifests");
  assert.equal(dashDocs.releaseVersion(), versionOf("launcher"));
});

test("the card's links are the user guide and its Troubleshooting heading", () => {
  const about = homeAbout(versionOf("launcher"));
  assert.equal(about.guideUrl, launcherDocs.docsUrl("docs/usage.md"));
  assert.equal(about.troubleshootingUrl, launcherDocs.docsUrl("docs/usage.md#troubleshooting"));
  // GitHub's anchor for "## Troubleshooting" is #troubleshooting.
  assert.match(readFileSync(join(REPO, "docs", "usage.md"), "utf8"), /^## Troubleshooting$/m);
});
