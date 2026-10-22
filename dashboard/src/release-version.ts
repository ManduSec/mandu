/**
 * release-version — the Mandu release this dashboard's code belongs to, and
 * where its help lives, for Settings › About Mandu (dashboard.md §4.25
 * *About Mandu*).
 *
 * The product carries ONE version in every manifest (packaging.md §11.2,
 * `launcher/test/unit/version-parity.test.ts`). The dashboard reads it from
 * the package.json one level above its own module: from source that is
 * `dashboard/package.json` (this file is `dashboard/src/release-version.ts`);
 * in the bundle it is the package root beside `dist/` (`dist/dashboard.mjs`
 * → `<pkg>/package.json`; in a checkout's own build, `launcher/package.json`).
 * "unknown" when the file cannot be read: the page then says how to find
 * the version, never an empty row.
 *
 * `DOCS_BASE_URL` / `docsUrl` mirror launcher/src/docs-url.ts: the dashboard
 * ships standalone and does not import the launcher package (as
 * agent-versions.ts says of its own mirror). tests/stack/about-mandu-parity keeps
 * the two equal.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code; mirrors
 * arbiter/ipc/release-version.ts `releaseVersion` and
 * launcher/src/docs-url.ts.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The public repository's tree at its default branch, ending in `/`. */
export const DOCS_BASE_URL = "https://github.com/mandusec/mandu/blob/main/";

/** The public URL of a repo-relative document path (`docs/usage.md`, `docs/usage.md#troubleshooting`). */
export function docsUrl(path: string): string {
  return DOCS_BASE_URL + path.replace(/^(\.\/|\/)+/, "");
}

/** The version in the package.json at `pkgPath`, or "unknown" when the file
 *  cannot be read or parsed or names no version. Not cached. */
export function readReleaseVersion(pkgPath: string): string {
  try {
    const v = (JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: unknown }).version;
    return typeof v === "string" && v.trim() !== "" ? v.trim() : "unknown";
  } catch {
    return "unknown";
  }
}

/** The package.json `releaseVersion` reads: one level above this module. */
export const RELEASE_PACKAGE_JSON = resolve(dirname(fileURLToPath(import.meta.url)), "..", "package.json");

/** A getter of the version in the package.json at `pkgPath` that reads the
 *  file once, on its first call, and answers the same after. */
export function releaseVersionFrom(pkgPath: string): () => string {
  let cached: string | undefined;
  return () => (cached ??= readReleaseVersion(pkgPath));
}

/** The release version (`0.2.0-beta.7`), or "unknown". Read once. */
export const releaseVersion: () => string = releaseVersionFrom(RELEASE_PACKAGE_JSON);
