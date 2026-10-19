/**
 * control-names — a control's accessible name as a browser computes it, for
 * the cases the inspector's panels draw (dashboard.md §4.32 *A row's control
 * names its row*). jsdom has no accessibility tree, so the jsdom tests and
 * the served-page stack test read names with this. Mandu-new.
 *
 * The order is the accessible-name computation's, cut to what is drawn:
 * `aria-labelledby`, `aria-label`, a wrapping `<label>`'s own words (its
 * control left out), a button's words (a `role="button"` element's too,
 * an SVG one's `<title>`), else a field's placeholder (a browser's last
 * resort).
 *
 * `scrollStops` / `scrollFaults` find the boxes that scroll with nothing to
 * focus in them, and the ones of those with no role or name (the product
 * page's, dashboard.md §4.25 *A box that scrolls says what it holds*).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

const squash = (s: unknown): string => String(s ?? "").replace(/\s+/g, " ").trim();

export function controlName(c: El): string {
  const doc = c.ownerDocument;
  const by = c.getAttribute("aria-labelledby");
  if (by) return squash(by.split(/\s+/).map((id: string) => doc.getElementById(id)?.textContent ?? "").join(" "));
  const label = c.getAttribute("aria-label");
  if (label) return squash(label);
  const wrap = c.closest("label");
  if (wrap) {
    const copy = wrap.cloneNode(true);
    copy.querySelectorAll("select, input, textarea").forEach((n: El) => n.remove());
    const words = squash(copy.textContent);
    if (words) return words;
  }
  if (c.tagName === "BUTTON" || c.getAttribute("role") === "button") {
    // A button is named by its content; an SVG one by its <title> (SVG-AAM).
    const title = c.namespaceURI === "http://www.w3.org/2000/svg" ? c.querySelector(":scope > title") : null;
    return squash(title ? title.textContent : c.textContent);
  }
  return squash(c.getAttribute("placeholder"));
}

/** A control's accessible description from `aria-describedby`: the words
 *  of each element it names, in order (a held message's or a finding's
 *  answers are described by their row's cells, dashboard.md §4.32). */
export function controlDescription(c: El): string {
  const by = c.getAttribute("aria-describedby");
  if (!by) return "";
  return squash(by.split(/\s+/).map((id: string) => c.ownerDocument.getElementById(id)?.textContent ?? "").join(" "));
}

/** Every control under `root` a person can reach: not in a `[hidden]`
 *  subtree, not disabled. */
export function reachableControls(root: El): El[] {
  return [...root.querySelectorAll("button, select, input, textarea")].filter((c: El) => !c.disabled && !c.closest("[hidden]"));
}

/** The names two or more controls under `root` share, and the controls
 *  with no name, as readable lines (both empty when every control says
 *  which it is). */
export function nameFaults(root: El): { shared: string[]; unnamed: string[] } {
  const seen = new Map<string, number>();
  const unnamed: string[] = [];
  for (const c of reachableControls(root)) {
    const name = controlName(c);
    if (!name) unnamed.push(`<${c.tagName.toLowerCase()} class="${c.className}">`);
    const key = `${c.tagName.toLowerCase()} "${name}"`;
    seen.set(key, (seen.get(key) ?? 0) + 1);
  }
  return { shared: [...seen].filter(([, n]) => n > 1).map(([k, n]) => `${n}× ${k}`), unnamed };
}

const FOCUSABLE = "a[href], button, input, select, textarea, summary, [tabindex]";
const scrolls = (v: string) => v === "auto" || v === "scroll";

/** Each element under `root`, shown, that may scroll (its computed overflow
 *  auto or scroll: the page's styles must be applied), holds something and
 *  holds nothing to focus: a Tab stop of its own in Chromium once it
 *  overflows (dashboard.md §4.25 *A box that scrolls says what it holds*). */
export function scrollStops(root: El): El[] {
  const css = (e: El) => root.ownerDocument.defaultView.getComputedStyle(e);
  return [...root.querySelectorAll("*")].filter((e: El) => !e.closest("[hidden]")
    && [css(e).overflow, css(e).overflowX, css(e).overflowY].some(scrolls)
    && squash(e.textContent) !== ""
    && !e.querySelector(FOCUSABLE));
}

/** A box's role: the attribute, else a list's own; anything else generic. */
export function boxRole(e: El): string {
  return e.getAttribute("role") ?? (e.tagName === "OL" || e.tagName === "UL" ? "list" : "generic");
}

/** The stops under `root` with no role or no name, as readable lines (empty
 *  when each says what it holds). */
export function scrollFaults(root: El): string[] {
  return scrollStops(root).filter((e) => boxRole(e) === "generic" || !controlName(e))
    .map((e) => `<${e.tagName.toLowerCase()} id="${e.id}" class="${e.className}"> role=${boxRole(e)} name="${controlName(e)}"`);
}
