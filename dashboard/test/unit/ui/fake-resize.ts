/**
 * fake-resize — a ResizeObserver for jsdom, which has none and lays out
 * nothing. `install(window)` before the page's script runs; each observer
 * is kept with the elements it watches, and `resized(el)` runs every
 * callback watching `el`, as a browser does once the element's box changed
 * size (shown, hidden, grown). Used by home-js-bar-room.test.ts and
 * tests/stack/rules-bar-room. Mandu-new.
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any;

export interface FakeResize {
  /** Give `w` this ResizeObserver. */
  install(w: Any): void;
  /** Run every callback watching `el`. */
  resized(el: Any): void;
  /** Is `el` watched? */
  watched(el: Any): boolean;
}

export function fakeResize(): FakeResize {
  const watching: Array<{ el: Any; observer: Any; cb: (entries: unknown[], observer: unknown) => void }> = [];
  return {
    install(w) {
      w.ResizeObserver = class {
        private readonly cb: (entries: unknown[], observer: unknown) => void;
        constructor(cb: (entries: unknown[], observer: unknown) => void) { this.cb = cb; }
        observe(el: Any): void { watching.push({ el, observer: this, cb: this.cb }); }
        unobserve(el: Any): void {
          for (let i = watching.length - 1; i >= 0; i -= 1) if (watching[i]!.observer === this && watching[i]!.el === el) watching.splice(i, 1);
        }
        disconnect(): void {
          for (let i = watching.length - 1; i >= 0; i -= 1) if (watching[i]!.observer === this) watching.splice(i, 1);
        }
      };
    },
    resized(el) {
      for (const x of watching.filter((x) => x.el === el)) x.cb([{ target: el }], x.observer);
    },
    watched(el) {
      return watching.some((x) => x.el === el);
    },
  };
}
