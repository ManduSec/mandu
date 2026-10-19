/**
 * page-wait.ts — how long a component test waits for a served page (run in
 * jsdom against the real DashboardServer) to render what it asserts.
 *
 * The page renders after its fetches answer and after jsdom has run the whole
 * home.js; on an idle host that is well under a second, on the loaded CI
 * guest it took 8 to 12 s, past the old 2 s, 5 s and 10 s waits ("six waiting
 * cards (got 0)", "the Home card carries a Details link", pipelines 9422,
 * 9531, 9532; test-organization.md §8.4). The wait is on the condition, so a
 * passing run is not slowed; only a page that never renders the thing waits
 * the whole budget, and then fails as before.
 */

/** The budget for one wait on a rendered page. */
export const PAGE_WAIT_MS = 60_000;

/** Poll every 20 ms while `busy()` holds, up to `ms`. The caller asserts
 *  what it waited for afterwards. */
export async function waitWhile(busy: () => boolean, ms: number = PAGE_WAIT_MS): Promise<void> {
  const end = Date.now() + ms;
  while (busy() && Date.now() < end) await new Promise((r) => setTimeout(r, 20));
}

/** How often `pollWhile` polls: well under the page's own POLL_MS (10 s). */
export const POLL_EVERY_MS = 2_000;

/** Stand in for the page's own poll, which the served-page harness stubs
 *  (`setInterval`): call `poll()` now, then every `everyMs` while `busy()`
 *  holds, up to `ms`; the caller asserts afterwards. For a step that waits
 *  on a return the page sees through a Home poll: a lone poll can land
 *  while a component that just started again is not answering yet, as the
 *  loaded CI guest showed (product-files-again-pages, pipelines 10830,
 *  10832, 10836), and in the product the next poll is what reads again. */
export async function pollWhile(
  busy: () => boolean,
  poll: () => void,
  everyMs: number = POLL_EVERY_MS,
  ms: number = PAGE_WAIT_MS,
): Promise<number> {
  const end = Date.now() + ms;
  let polls = 0;
  let next = 0;
  while (busy() && Date.now() < end) {
    if (Date.now() >= next) { poll(); polls += 1; next = Date.now() + everyMs; }
    await new Promise((r) => setTimeout(r, 20));
  }
  return polls;
}
