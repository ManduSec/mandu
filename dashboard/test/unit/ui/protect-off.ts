/**
 * protect-off — turn the Protection switch off the way a person does since
 * 2026-10-25 (dashboard.md §4.25 *Turning protection off asks on the
 * page*): press the switch, which opens the OFF box in its row, type the
 * word, and press Enter in the box (or Turn off). For the jsdom tests over
 * home.js and the served page.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** The OFF box in the Protection row, or null while it is closed. */
export function offBox(doc: Doc): { box: Doc; input: Doc; turnOff: Doc; cancel: Doc; hint: Doc } | null {
  const box = doc.getElementById("settings-protect-confirm");
  if (!box || box.hidden) return null;
  const button = (label: string) => [...box.querySelectorAll("button")].find((b: Doc) => b.textContent === label);
  return { box, input: box.querySelector("input"), turnOff: button("Turn off"), cancel: button("Cancel"), hint: box.querySelector(".confirm-hint") };
}

/** Type `word` in the open OFF box, as each key would. */
export function typeInOffBox(doc: Doc, word: string): void {
  const open = offBox(doc);
  if (!open) throw new Error("the OFF box is not open");
  open.input.value = word;
  open.input.dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
}

/** Enter in the OFF box. */
export function enterInOffBox(doc: Doc): void {
  const open = offBox(doc);
  if (!open) throw new Error("the OFF box is not open");
  open.input.dispatchEvent(new doc.defaultView.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
}

/** Press the switch (the focus on it first), type `word` in the box it
 *  opens, and press Enter there. */
export function turnOffTyped(doc: Doc, word = "OFF"): void {
  const sw = doc.getElementById("switch-protection");
  sw.focus();
  sw.click();
  typeInOffBox(doc, word);
  enterInOffBox(doc);
}
