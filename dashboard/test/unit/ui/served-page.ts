/**
 * served-page — the SERVED product page in jsdom: a real DashboardServer's
 * own index.html and js/home.js, with the page's fetch bridged to that
 * server (dashboard.md §4.25). For suites outside this package that render
 * the product page over real components (tests/stack/home-waiting-verdict),
 * as the inspector's harness does for its page; jsdom is this package's
 * dependency, so the page is loaded here. The component suites keep their
 * own copies (home-counts.test.ts `servedPage`). The developer view loads
 * its pages with a helper of its own.
 */
import { JSDOM } from "jsdom";

import { PAGE_WAIT_MS, waitWhile } from "../page-wait.js";
import { pageFetch } from "../page-fetch.js";

/** What the page is opened with: `headers` go with every request it makes
 *  (a signed-in browser's cookie), and `css` is applied as its styles (jsdom
 *  does not fetch the page's stylesheet links). */
export interface ServedPageOptions {
  headers?: Record<string, string>;
  css?: string;
  /** Runs on the window before any of the page's scripts, so what they
   *  read at boot is already in place (a ResizeObserver, fake-resize.ts:
   *  tests/stack/rules-bar-room). */
  beforeScripts?: (window: any) => void; // eslint-disable-line @typescript-eslint/no-explicit-any
}


/** The page at `base + path` in jsdom; `fn` runs once `ready` holds (or the
 *  page-wait budget is spent), then the window closes. A late answer never
 *  reaches a closed window. */
export async function servedProductPage(
  base: string,
  path: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ready: (doc: any) => boolean,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  fn: (doc: any) => void | Promise<void>,
  opts: ServedPageOptions = {},
): Promise<void> {
  const extra = opts.headers ?? {};
  const html = await (await pageFetch(`${base}${path}`, { headers: extra })).text();
  const js = await (await pageFetch(`${base}/js/home.js`, { headers: extra })).text();
  const dom = new JSDOM(html.replace(/<script type="module"[^>]*><\/script>/, ""), { url: `${base}${path}`, runScripts: "outside-only", pretendToBeVisual: true });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const w = dom.window as any;
  if (opts.css !== undefined) {
    const style = w.document.createElement("style");
    style.textContent = opts.css;
    w.document.head.append(style);
  }
  let closed = false;
  const gate = <T>(p: Promise<T>): Promise<T> =>
    p.then((v) => (closed ? new Promise<T>(() => {}) : v), (e) => (closed ? new Promise<T>(() => {}) : Promise.reject(e)));
  w.fetch = (url: string, { signal: _signal, headers, ...init }: RequestInit = {}) =>
    gate(pageFetch(new URL(url, base).href, { ...init, headers: { ...(headers as Record<string, string> | undefined), ...extra } }).then(async (res) => {
      const body = await res.text();
      return { ok: res.ok, status: res.status, json: () => gate(Promise.resolve().then(() => JSON.parse(body))) };
    }));
  w.setInterval = () => 0;
  w.scrollTo = () => {};
  opts.beforeScripts?.(w);
  w.eval(js);
  try {
    const doc = w.document;
    await waitWhile(() => !ready(doc));
    // A page that never drew it fails here, by name, not in the test's
    // first query of a card that is not there (pipeline 10302: a TypeError
    // after the whole wait).
    if (!ready(doc)) throw new Error(`the served page ${path} never drew what the test waits for (${PAGE_WAIT_MS / 1000} s)`);
    await fn(doc);
  } finally {
    closed = true;
    w.close();
  }
}

/** A page from its own `html` in jsdom at `url`, `css` applied as its
 *  styles, no script run: for a suite outside this package that runs a
 *  page's own code on it (tests/stack/settings-appearance runs the developer
 *  view's Appearance code over the product page's stored choice). The
 *  caller closes the window. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function pageFromHtml(html: string, url: string, css?: string): any {
  const w = new JSDOM(html, { url, runScripts: "outside-only", pretendToBeVisual: true }).window;
  if (css !== undefined) {
    const style = w.document.createElement("style");
    style.textContent = css;
    w.document.head.append(style);
  }
  return w;
}
