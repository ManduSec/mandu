/**
 * lifeline.test — the kernel-bound lifetime watcher (lifeline.ts).
 *
 * Duplicated alongside its module in each service package (the copies must not
 * drift silently — each package's suite proves ITS copy). The kernel-EOF
 * delivery itself is proven live in launcher/test/component/lifeline.test.ts; these
 * cover the arming contract.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { armLifeline, type LifelineStream } from "../../ipc/lifeline.js";

class FakeStdin implements LifelineStream {
  isTTY: boolean | undefined;
  resumed = 0;
  unrefed = 0;
  private listeners = new Map<string, Array<() => void>>();
  constructor(isTTY?: boolean) { this.isTTY = isTTY; }
  once(event: "end" | "error", listener: () => void): this {
    const l = this.listeners.get(event) ?? [];
    l.push(listener);
    this.listeners.set(event, l);
    return this;
  }
  resume(): this { this.resumed++; return this; }
  unref(): this { this.unrefed++; return this; }
  emit(event: "end" | "error"): void {
    const l = this.listeners.get(event) ?? [];
    this.listeners.delete(event); // node's once() semantics
    for (const fn of l) fn();
  }
}

test("absent env: arms nothing, never touches stdin", () => {
  const stdin = new FakeStdin();
  let fired = 0;
  assert.equal(armLifeline(() => fired++, {}, stdin), false);
  stdin.emit("end");
  assert.equal(fired, 0);
  assert.equal(stdin.resumed, 0);
});

test("wrong value: arms nothing (only the exact contract 'stdin')", () => {
  const stdin = new FakeStdin();
  assert.equal(armLifeline(() => {}, { MANDU_LIFELINE: "1" }, stdin), false);
  assert.equal(stdin.resumed, 0);
});

test("TTY stdin refuses to arm even with the env set (leaked-env fence)", () => {
  const stdin = new FakeStdin(true);
  let fired = 0;
  assert.equal(armLifeline(() => fired++, { MANDU_LIFELINE: "stdin" }, stdin), false);
  stdin.emit("end");
  assert.equal(fired, 0);
  assert.equal(stdin.resumed, 0);
});

test("armed: EOF fires onSevered once; stream resumed + unref'd", () => {
  const stdin = new FakeStdin(false);
  let fired = 0;
  assert.equal(armLifeline(() => fired++, { MANDU_LIFELINE: "stdin" }, stdin), true);
  assert.equal(stdin.resumed, 1); // flowing, so 'end' can fire
  assert.equal(stdin.unrefed, 1); // must not keep a closing loop alive
  stdin.emit("end");
  assert.equal(fired, 1);
});

test("armed: end THEN error still fires onSevered exactly once", () => {
  const stdin = new FakeStdin();
  let fired = 0;
  assert.equal(armLifeline(() => fired++, { MANDU_LIFELINE: "stdin" }, stdin), true);
  stdin.emit("end");
  stdin.emit("error");
  assert.equal(fired, 1);
});

test("armed: a torn pipe (error) alone also severs", () => {
  const stdin = new FakeStdin();
  let fired = 0;
  armLifeline(() => fired++, { MANDU_LIFELINE: "stdin" }, stdin);
  stdin.emit("error");
  assert.equal(fired, 1);
});
