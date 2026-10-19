/**
 * dev-pages — where this tree's developer view keeps its pages, for the
 * suites that check both front-ends' stylesheets and scripts (dashboard.md
 * §4.25ac). Found as the server finds the developer view
 * (extension-loader.ts `resolveExtensionModule`): its pages are `dev/` of
 * the package whose `src/<dir>/index.ts` that module is. A
 * tree without it (the public one) has none: the developer view's half of
 * each check is skipped, and the product's half runs.
 */
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { resolveExtensionModule } from "../../../src/extension-loader.js";

const SRC = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "..", "src");

/** The developer view's pages, or null when this tree has none.
 *  `MANDU_TEST_NO_DEV_PAGES=1` answers null in any tree, to run these
 *  suites as the public tree runs them. */
export function devPagesDir(): string | null {
  if (process.env["MANDU_TEST_NO_DEV_PAGES"] === "1") return null;
  const mod = resolveExtensionModule(SRC);
  if (mod === null) return null;
  const dir = join(dirname(mod), "..", "..", "dev");
  return existsSync(join(dir, "index.html")) ? dir : null;
}

/** Skip a developer-view check where there is no developer view. */
export const NO_DEV_PAGES = devPagesDir() === null ? "no developer view in this tree" : false;
