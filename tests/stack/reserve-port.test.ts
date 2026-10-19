/**
 * reserve-port.test — the live lane's race-free ports (test-organization.md
 * §8.4): the launcher-routed suites run the proxy on port 0 and read the port
 * it published back (publishedProxyPort); the differential harness, which
 * must name a port before the launch, reserves one (reservePort). Also the
 * drift check for the per-package copies of reserve-port.ts, which must stay
 * identical (each package keeps its own; there is no shared workspace).
 * Deterministic: loopback sockets and temp files only, no agent, no arbiter.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { connect, createServer } from "node:net";
import { createSocket } from "node:dgram";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { publishedProxyPort } from "../lib/launcher-live.js";
import { ephemeralRange, reservePort } from "../lib/reserve-port.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("off"); // this suite states its axes (protection-modes.md §4); no arbiter is involved

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

const refused = (port: number): Promise<string> => new Promise((res) => {
  const s = connect({ port, host: "127.0.0.1" });
  s.once("connect", () => { s.destroy(); res("connected"); });
  s.once("error", (e: NodeJS.ErrnoException) => res(e.code ?? "error"));
});

test("reservePort: outside the ephemeral range, refused until used, claimed, and listenable", async () => {
  const { low, high } = ephemeralRange();
  const port = await reservePort();
  assert.ok(port < low || port > high, `${port} is outside ${low}-${high}`);
  assert.equal(await refused(port), "ECONNREFUSED");
  const claim = await new Promise<string>((res) => {
    const s = createSocket({ type: "udp4", reuseAddr: false });
    s.once("error", (e: NodeJS.ErrnoException) => res(e.code ?? "error"));
    s.bind({ port, address: "127.0.0.1" }, () => { s.close(); res("bound"); });
  });
  assert.equal(claim, "EADDRINUSE", "no other reservation can take the port");
  assert.notEqual(await reservePort(), port);
  const srv = createServer();
  await new Promise<void>((res, rej) => { srv.once("error", rej); srv.listen(port, "127.0.0.1", () => res()); });
  await new Promise<void>((res) => srv.close(() => res()));
});

test("publishedProxyPort: reads the one port file the launch's proxy published", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-published-port-"));
  try {
    assert.throws(() => publishedProxyPort(tmp), /expected one anthropic-proxy\.port/);
    mkdirSync(join(tmp, "mandu", "scope-a"), { recursive: true });
    writeFileSync(join(tmp, "mandu", "scope-a", "anthropic-proxy.port"), "41234\n");
    assert.equal(publishedProxyPort(tmp), 41234);
    mkdirSync(join(tmp, "mandu", "scope-b"), { recursive: true });
    writeFileSync(join(tmp, "mandu", "scope-b", "anthropic-proxy.port"), "41235\n");
    assert.throws(() => publishedProxyPort(tmp), /found 2/, "two launches' files are ambiguous");
    rmSync(join(tmp, "mandu", "scope-b"), { recursive: true });
    writeFileSync(join(tmp, "mandu", "scope-a", "anthropic-proxy.port"), "not-a-port\n");
    assert.throws(() => publishedProxyPort(tmp), /holds no port/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the per-package copies of reserve-port.ts are identical", () => {
  const copies = [
    "tests/lib/reserve-port.ts",
    "launcher/test/lib/reserve-port.ts",
    "dashboard/test/unit/reserve-port.ts",
    "interceptors/inspect-mcp/test/helpers/reserve-port.ts",
  ];
  const [first, ...rest] = copies.map((p) => readFileSync(join(REPO_ROOT, p), "utf8"));
  rest.forEach((body, i) => assert.equal(body, first, `${copies[i + 1]} drifted from ${copies[0]}`));
  // Every copy is named in the header, so an edit finds the others.
  for (const p of copies) assert.ok(first!.includes(p), `the header names ${p}`);
});
