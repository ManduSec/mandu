/**
 * reserve-port — the race-free port reservation the inspect-mcp tests use for a
 * dead endpoint (test-organization.md §8.4): below the ephemeral range,
 * claimed against every other reservation, nothing listening, still usable.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createSocket } from "node:dgram";
import { connect, createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { candidateRange, ephemeralRange, reservePort } from "../helpers/reserve-port.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const TSX = join(HERE, "..", "..", "node_modules", ".bin", "tsx");

/** Try the claim another reservation would take: its error code, or "bound". */
const claimOutcome = (port: number): Promise<string> => new Promise((res) => {
  const s = createSocket({ type: "udp4", reuseAddr: false });
  s.once("error", (e: NodeJS.ErrnoException) => res(e.code ?? "error"));
  s.bind({ port, address: "127.0.0.1" }, () => { s.close(); res("bound"); });
});

const refused = (port: number): Promise<string> => new Promise((res) => {
  const s = connect({ port, host: "127.0.0.1" });
  s.once("connect", () => { s.destroy(); res("connected"); });
  s.once("error", (e: NodeJS.ErrnoException) => res(e.code ?? "error"));
});

test("the candidates sit outside the ephemeral range, below it when there is room", () => {
  assert.deepEqual(candidateRange({ low: 32768, high: 60999 }), { from: 24576, to: 32767 });
  assert.deepEqual(candidateRange({ low: 2048, high: 60999 }), { from: 1024, to: 2047 });
  assert.deepEqual(candidateRange({ low: 1024, high: 60000 }), { from: 60001, to: 65535 });
  assert.equal(candidateRange({ low: 1024, high: 65535 }), null);
  const { low, high } = ephemeralRange();
  assert.ok(low > 0 && high >= low);
});

test("a reserved port is outside the ephemeral range and refuses connections", async () => {
  const { low, high } = ephemeralRange();
  const port = await reservePort();
  assert.ok(port < low || port > high, `${port} is outside ${low}-${high}`);
  assert.equal(await refused(port), "ECONNREFUSED");
});

test("the claim keeps every other reservation off the port, and the port stays usable", async () => {
  const port = await reservePort();
  // Another claimer (this process or any other copy of the helper) fails.
  assert.equal(await claimOutcome(port), "EADDRINUSE");
  const seen = new Set<number>([port]);
  for (let i = 0; i < 20; i++) {
    const p = await reservePort();
    assert.ok(!seen.has(p), `port ${p} reserved twice`);
    seen.add(p);
  }
  // The server the port is meant for can still listen on it.
  const srv = createServer();
  await new Promise<void>((res, rej) => { srv.once("error", rej); srv.listen(port, "127.0.0.1", () => res()); });
  await new Promise<void>((res) => srv.close(() => res()));
});

test("another process's live reservation cannot be claimed here", async () => {
  // The child reserves a port, prints it, and holds it until its stdin closes.
  const lib = join(HERE, "..", "helpers", "reserve-port.ts");
  const child = spawn(TSX, ["-e", `import("${lib}").then(async (m) => {
    console.log(await m.reservePort());
    process.stdin.resume(); process.stdin.on("end", () => process.exit(0));
  });`], { stdio: ["pipe", "pipe", "inherit"] });
  try {
    const [line] = (await once(child.stdout!, "data")) as [Buffer];
    const port = Number(line.toString().trim());
    assert.ok(port > 0, `the child reported a port, got '${line}'`);
    assert.equal(await claimOutcome(port), "EADDRINUSE", "the child's claim holds across processes");
  } finally {
    child.stdin!.end();
    await once(child, "exit");
  }
});
