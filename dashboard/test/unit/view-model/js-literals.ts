/**
 * js-literals — every string and template literal of a script, read with the
 * TypeScript compiler, for the sweeps that check the product's copy. A comment
 * or a regex is never a literal, so an apostrophe in one cannot shift what
 * counts as a string (the quote-pairing sweeps this replaced could be fooled
 * that way), and every quote style is read: '…', "…" and `…`.
 * Shared by home-view-model.test.ts and product-words.test.ts.
 */

import { readFileSync } from "node:fs";
import ts from "typescript";

/** A literal's text and its 1-based line. */
export interface Literal { text: string; line: number }

/** Every string and template literal in `file` (or in `source`, read as that
 *  file), with its line. A template with substitutions gives each of its
 *  literal parts. */
export function literals(file: string, source = readFileSync(file, "utf8")): Literal[] {
  const src = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, file.endsWith(".js") ? ts.ScriptKind.JS : ts.ScriptKind.TS);
  const out: Literal[] = [];
  const add = (n: ts.Node, text: string) => out.push({ text, line: src.getLineAndCharacterOfPosition(n.getStart(src)).line + 1 });
  const walk = (n: ts.Node): void => {
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) add(n, n.text);
    else if (ts.isTemplateExpression(n)) {
      add(n.head, n.head.text);
      for (const span of n.templateSpans) add(span.literal, span.literal.text);
    }
    ts.forEachChild(n, walk);
  };
  walk(src);
  return out;
}
