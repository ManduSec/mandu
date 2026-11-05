/**
 * about-mandu-parity — Settings › About Mandu's facts are the launcher's
 * (dashboard.md §4.25 *About Mandu*). The dashboard ships standalone and
 * mirrors the launcher's docs base (launcher/src/docs-url.ts) rather than
 * importing it, as it mirrors the tested-version table
 * (agent-versions-parity.test.ts, beside this one in the docs lane). This
 * keeps the mirrors equal, the issue tracker one address, its bug form a
 * template that exists with a `version` field, the private
 * security report form on the same repository, the release the
 * card shows the one every manifest names, and the user guide's
 * Troubleshooting heading where the card's link lands. Pure: no server, no
 * arbiter, nothing enforced, so no axis is in play. Mandu-new.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
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

test("Report a problem opens the launcher's tracker's bug form, a template that exists, with its version field filled in", () => {
  const url = homeAbout("1.0.0").bugReportUrl;
  assert.ok(url.startsWith(launcherVersions.ISSUES_URL + "/new?"), url);
  const params = new URL(url).searchParams;
  assert.equal(params.get("version"), "1.0.0");
  // The template named is a file in the repository's issue templates (read
  // from the directory, so renaming it fails here)…
  const template = params.get("template");
  assert.ok(template && readdirSync(join(REPO, ".github", "ISSUE_TEMPLATE")).includes(template), `${template} is an issue template`);
  // …and the field GitHub fills from the address is still its `version`
  // input (GitHub fills a form field from a parameter named by its id).
  const form = readFileSync(join(REPO, ".github", "ISSUE_TEMPLATE", template!), "utf8");
  assert.match(form, /^\s*- type: input\n\s+id: version$/m, "the bug form's version field keeps the id version");
});

test("Report a security problem is the same repository's private vulnerability report form, not its issue tracker", () => {
  const issues = new URL(launcherVersions.ISSUES_URL);
  const repo = issues.pathname.replace(/\/issues\/?$/, "");
  assert.match(repo, /^\/[^/]+\/[^/]+$/, "the launcher's tracker names one owner and repository");
  assert.equal(dashVersions.SECURITY_REPORT_URL, `${issues.origin}${repo}/security/advisories/new`);
  assert.equal(homeAbout("1.0.0").securityUrl, dashVersions.SECURITY_REPORT_URL);
  assert.notEqual(homeAbout("1.0.0").securityUrl, homeAbout("1.0.0").issuesUrl);
  // The repository's own issue chooser sends a vulnerability to the same form.
  assert.ok(readFileSync(join(REPO, ".github", "ISSUE_TEMPLATE", "config.yml"), "utf8").includes(`url: ${dashVersions.SECURITY_REPORT_URL}`));
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
