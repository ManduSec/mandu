/**
 * issuers/index — the default catalog's issuer files, in table order
 * (confidentiality.md §2.3, "Where the table lives"). One JSON file per
 * issuer beside this module; `issuer-catalog.ts` checks and compiles them,
 * and `issuer-bindings.ts` exports the result as `ISSUERS`.
 *
 * The files are imported statically so every form of the arbiter reads the
 * same bytes: the source through tsx, `tsc`'s output, and each esbuild
 * bundle of the npm package (which inlines the JSON; no file is read at
 * run time). A new issuer is one new file plus one line here, appended
 * (the order is the table's, which `issuers_off` messages and the Rules
 * page print); `npm run check:issuers` and the unit test fail on a file in
 * the directory this list does not name, or a name with no file.
 *
 * Mandu-new (no reference origin).
 */
import stripe from "./stripe.json" with { type: "json" };
import github from "./github.json" with { type: "json" };
import notion from "./notion.json" with { type: "json" };
import openai from "./openai.json" with { type: "json" };
import slack from "./slack.json" with { type: "json" };
import npm from "./npm.json" with { type: "json" };
import pypi from "./pypi.json" with { type: "json" };
import huggingface from "./huggingface.json" with { type: "json" };
import sendgrid from "./sendgrid.json" with { type: "json" };

/** One issuer file as read: its file name and its parsed JSON (unchecked). */
export interface IssuerFile {
  file: string;
  data: unknown;
}

/** Every issuer file, in table order. */
export const ISSUER_FILES: readonly IssuerFile[] = [
  { file: "stripe.json", data: stripe },
  { file: "github.json", data: github },
  { file: "notion.json", data: notion },
  { file: "openai.json", data: openai },
  { file: "slack.json", data: slack },
  { file: "npm.json", data: npm },
  { file: "pypi.json", data: pypi },
  { file: "huggingface.json", data: huggingface },
  { file: "sendgrid.json", data: sendgrid },
];
