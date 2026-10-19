/**
 * docs-url — where user-facing text points for documentation.
 *
 * The npm package ships no `docs/` directory, so help text, hints and warnings
 * never name a repo-relative path like `docs/usage.md`: an installed user has
 * no such file. They name the document's public URL instead, built from this
 * one base so a move of the public repository or its default branch is a
 * one-line change (release checklist d7).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */

/** The public repository's tree at its default branch, ending in `/`. */
export const DOCS_BASE_URL = "https://github.com/mandusec/mandu/blob/main/";

/** The public URL of a repo-relative document path (`docs/usage.md`, `docs/design/x.md#anchor`). */
export function docsUrl(path: string): string {
  return DOCS_BASE_URL + path.replace(/^(\.\/|\/)+/, "");
}
