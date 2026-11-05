/**
 * retired-words — the words the product retired (dashboard.md §4.25u), for
 * the sweeps that read its copy: the page is Approvals, a secret file is
 * not a "locked file", a masked value is "masked" (never a "placeholder"),
 * and the person's computer is "this computer" (never "this machine").
 * Shared by home-view-model.test.ts and product-words.test.ts.
 */

/** The retired page and value words. */
export const RETIRED = new RegExp([
  /\bInbox\b/.source, // the page's old name (the "inbox" page key and ids are routing, lower-case)
  /\b[Tt]he inbox\b/.source,
  /\b[Ll]ocked[ -]files?\b/.source,
  /\b[Pp]laceholders?\b(?!\s*:)/.source, // not an <input>'s placeholder attribute
].join("|"));

/** "this machine": the product says "this computer". */
export const THIS_MACHINE = /\bthis machine\b/i;
