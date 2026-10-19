/**
 * config-edit — surgical edits of the protection keys (`mode`, `integrity`,
 * `confidentiality`) in `~/.mandu/config.toml`, for `mandu mode
 * <name>` (docs/design/architecture/protection-modes.md §3.2).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): a NARROW MIRROR of the dashboard's
 * surgical editor, dashboard/src/config-axes.ts (`applyManagedEdit`,
 * `applyModeEdit`, `writeMode`). Mirrored, not imported: the two packages
 * typecheck and ship standalone. The two hard rules are the same, and
 * tests/stack/axis-defaults-parity.test.ts feeds both editors the
 * same inputs and requires byte-identical output. Change them together.
 *
 *   - SURGICAL: a write touches only the managed lines (replaced in place,
 *     indent and inline comment preserved, every occurrence so the last-wins
 *     read stays coherent) or appends what is absent under one provenance
 *     comment (added once). Every other byte is the user's and is preserved.
 *   - SELF-CONSISTENT: writing a mode sets the `mode` line and RE-ALIGNS any
 *     axis line already in the file to that mode's pair (it never appends axis
 *     lines). Inside one level an axis key beats the mode, so a stale
 *     `integrity = true` left beside `mode = "secrets"` would silently win.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { MODE_AXES, type Mode } from "./mode.js";

export const MODE_PROVENANCE_COMMENT =
  "# mode below is managed by Mandu (`mandu mode`, or the dashboard's Protection drawer)";

function managedLineRe(key: string): RegExp {
  return new RegExp(`^([ \\t]*)${key}[ \\t]*=[ \\t]*([^\\r\\n]*)$`, "gm");
}

/** Replace every `key = …` line in place; returns [text, replacedAny]. */
function replaceManaged(text: string, key: string, rendered: string): [string, boolean] {
  let replaced = false;
  const out = text.replace(managedLineRe(key), (_m, indent: string, rest: string) => {
    replaced = true;
    // An inline comment survives. A `#` inside a quoted value is not a comment.
    const unquoted = rest.replace(/^(["'])[^"']*\1/, "");
    const hash = unquoted.indexOf("#");
    const inline = hash >= 0 ? `  ${unquoted.slice(hash)}` : "";
    return `${indent}${key} = ${rendered}${inline}`;
  });
  return [out, replaced];
}

/** Pure: apply `mode = "<name>"` to config TEXT (see the header's two rules). */
export function applyModeEdit(text: string, mode: Mode): string {
  let out = text;
  for (const axis of ["integrity", "confidentiality"] as const) {
    [out] = replaceManaged(out, axis, MODE_AXES[mode][axis] ? "true" : "false");
  }
  let replaced: boolean;
  [out, replaced] = replaceManaged(out, "mode", `"${mode}"`);
  if (!replaced) {
    if (out.length > 0 && !out.endsWith("\n")) out += "\n";
    if (!out.includes(MODE_PROVENANCE_COMMENT)) {
      out += (out.length > 0 ? "\n" : "") + MODE_PROVENANCE_COMMENT + "\n";
    }
    out += `mode = "${mode}"\n`;
  }
  return out;
}

/** Read-modify-write the config file (tmp + rename, parent dir created). */
export function writeModeToConfig(path: string, mode: Mode): void {
  mkdirSync(dirname(path), { recursive: true });
  const prior = existsSync(path) ? readFileSync(path, "utf8") : "";
  const tmp = `${path}.tmp-mode-${process.pid}`;
  writeFileSync(tmp, applyModeEdit(prior, mode));
  renameSync(tmp, path);
}
