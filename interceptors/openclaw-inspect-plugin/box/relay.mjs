#!/usr/bin/env node
// relay.mjs — the exec relay: the program OpenClaw spawns for each command
// when Mandu is its sandbox backend (docs/design/agents/openclaw-plugin.md
// §10). Mandu-new (no reference origin).
//
//   relay.mjs <box socket> <ticket>
//
// The plugin's buildExecSpec prepared the command with the box host (its
// text, folder, environment, terminal) and got a one-time ticket; this relay
// presents the ticket and becomes the command's stand-in on the Gateway's
// side: its stdin goes to the command, the command's stdout and stderr come
// back, and it exits with the command's status (128 + n for a signal). A
// signal it receives is passed on to the command's process group; the relay
// killed outright closes the connection, and the host kills the group.
//
// FAIL CLOSED: no box, a refused ticket or a broken connection, and the
// command does not run anywhere else: the relay says so on stderr and exits
// 126. It never runs the command itself.

import { connect } from "node:net";
import { constants } from "node:os";

import { FrameDecoder, T, encodeFrame, frameJson } from "./frames.mjs";

/** The relay's own exit when the command never ran (no box, refused). */
const EXIT_NOT_RUN = 126;

const [sockPath, ticket] = process.argv.slice(2);
if (!sockPath || !ticket) {
  process.stderr.write("mandu: the exec relay needs <box socket> <ticket>; the command did not run\n");
  process.exit(EXIT_NOT_RUN);
}

let gotExit = false;
let ran = false;
const sock = connect(sockPath);
const decoder = new FrameDecoder();

function notRun(why) {
  process.stderr.write(`mandu: the command did not run: ${why}. Mandu's confined-commands box runs every command of this OpenClaw agent; nothing ran outside it.\n`);
  process.exit(EXIT_NOT_RUN);
}

sock.on("connect", () => {
  sock.write(encodeFrame(T.REQUEST, { op: "run", ticket }));
  if (process.stdin.isTTY && typeof process.stdin.setRawMode === "function") {
    try { process.stdin.setRawMode(true); } catch { /* not a terminal after all */ }
  }
  process.stdin.on("data", (d) => { if (!sock.destroyed) sock.write(encodeFrame(T.STDIN, d)); });
  process.stdin.on("end", () => { if (!sock.destroyed) sock.write(encodeFrame(T.STDIN_END)); });
  process.stdin.on("error", () => { if (!sock.destroyed) sock.write(encodeFrame(T.STDIN_END)); });
});

sock.on("data", (chunk) => {
  let frames;
  try { frames = decoder.push(chunk); } catch (e) { notRun(`the box sent something the relay cannot read (${e.message})`); return; }
  for (const f of frames) {
    if (f.type === T.STDOUT) { ran = true; process.stdout.write(f.payload); }
    else if (f.type === T.STDERR) { ran = true; process.stderr.write(f.payload); }
    else if (f.type === T.FAIL) {
      const j = frameJson(f.payload);
      notRun(`the box refused it (${j?.error ?? "no reason given"})`);
    } else if (f.type === T.EXIT) {
      gotExit = true;
      const j = frameJson(f.payload) ?? {};
      const code = typeof j.code === "number" ? j.code
        : typeof j.signal === "string" && constants.signals[j.signal] !== undefined ? 128 + constants.signals[j.signal]
        : 1;
      // Let stdout and stderr drain before the exit.
      process.stdout.write("", () => process.stderr.write("", () => process.exit(code)));
    }
  }
});

sock.on("error", (e) => {
  if (gotExit) return;
  notRun(`Mandu's confined-commands box is not reachable (${e.message})`);
});
sock.on("close", () => {
  if (gotExit) return;
  if (!ran) notRun("Mandu's confined-commands box closed the connection");
  process.stderr.write("mandu: the confined-commands box closed the connection before the command finished\n");
  process.exit(EXIT_NOT_RUN);
});

for (const sig of ["SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT"]) {
  process.on(sig, () => {
    if (!sock.destroyed) sock.write(encodeFrame(T.SIGNAL, { signal: sig }));
  });
}
