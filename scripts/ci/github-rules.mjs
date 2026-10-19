// scripts/ci/github-rules.mjs — GitHub's `paths:` filter semantics
// (docs/design/testing/continuous-integration.md §12, "When GitHub runs").
//
// scripts/test/suites-manifest.test.mjs checks `ci.yml`'s pull-request
// `paths` filter against the GitLab docs lane (lane.mjs isDocsPath) over every
// tracked file with this matcher, so the two cannot drift.
//
// Patterns use GitHub's filter syntax (`*` within one path segment, `**`
// across segments, a leading `**/` also matching the repository root, `!` to
// exclude in an ordered list). `?`, `+` and `[…]` mean something else to
// GitHub than to a shell, so no pattern here uses them (globRegex refuses
// them).
//
// GitHub runs no macOS suite (decided 2026-10-09): the maintainers run the
// manifest's darwin entries on a Mac by hand (development.md, "Developing and
// testing on macOS").

/** A GitHub filter pattern as an anchored RegExp. */
export function globRegex(glob) {
  if (/[?+[\]]/.test(glob)) throw new Error(`${glob}: ? + [ ] mean something else to GitHub; not used here`);
  if (glob.startsWith("!")) throw new Error(`${glob}: a negation belongs to an ordered list (filterMatch)`);
  let re = "";
  for (let i = 0; i < glob.length;) {
    if (glob.startsWith("**/", i)) { re += "(?:.*/)?"; i += 3; continue; }
    if (glob.startsWith("**", i)) { re += ".*"; i += 2; continue; }
    if (glob[i] === "*") { re += "[^/]*"; i += 1; continue; }
    re += glob[i].replace(/[.^$|(){}\\]/g, "\\$&");
    i += 1;
  }
  return new RegExp(`^${re}$`);
}

/** Does a path match one pattern? */
export function globMatch(glob, path) {
  return globRegex(glob).test(path);
}

/**
 * GitHub's ordered `paths:` semantics: a path is selected by the last pattern
 * that matches it; a `!pattern` deselects. A path no pattern matches is not
 * selected.
 */
export function filterMatch(patterns, path) {
  let on = false;
  for (const p of patterns) {
    const neg = p.startsWith("!");
    if (globMatch(neg ? p.slice(1) : p, path)) on = !neg;
  }
  return on;
}
