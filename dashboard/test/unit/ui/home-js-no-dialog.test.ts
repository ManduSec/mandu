/**
 * The product page asks every question on the page, never in the browser's
 * own dialog (dashboard.md §4.25n *Rules asks on the page, not in a browser
 * dialog*): a browser told to stop showing dialogs answers window.confirm
 * "no" at once, unseen, and the button that asked did nothing. Until
 * 2026-10-26 Settings (Models, Sensitivity labels, Prompt filters) and Let
 * it through under a message still asked there. The jsdom fixture makes
 * both dialogs throw; this reads the page's script, so no new call creeps
 * in where no test presses.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
const JS = readFileSync(fileURLToPath(new URL("../../../public/js/home.js", import.meta.url)), "utf8");

test("home.js calls neither window.confirm, window.prompt nor alert", () => {
  // Comments may name them (the history of a question); code never calls them.
  const code = JS.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:\\])\/\/.*$/gm, "$1");
  assert.ok(code.includes("function askBox("), "the comments went, the code stayed");
  for (const name of ["confirm", "prompt", "alert"]) {
    const call = new RegExp(`(?:^|[^.\\w$])(?:window\\.)?${name}\\s*\\(`, "m");
    assert.equal(call.test(code), false, `a ${name}( call`);
  }
});
