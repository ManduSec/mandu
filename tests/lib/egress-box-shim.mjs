/**
 * egress-box-shim — runs one command INSIDE an egress box from outside it
 * (egress-box.ts `shim`): a program that spawns, say, `openclaw` from PATH
 * (Mandu's launcher) gets this in its place, and the real binary runs in the
 * box with this process's argv, environment and working directory, its
 * output relayed and its exit status returned. SIGTERM / SIGINT / SIGHUP
 * reach the command's process group in the box; this process ending ends
 * the command (the box kills a command whose control connection closed).
 *
 * NEW Mandu test code (no reference origin).
 *
 *   node egress-box-shim.mjs <ctl.sock> <real binary> [args…]
 */
import { connect } from "node:net";

const [ctlPath, real, ...args] = process.argv.slice(2);
const conn = connect(ctlPath);
let buf = "";
let code = 255;
conn.on("connect", () => {
  conn.write(JSON.stringify({ op: "exec", argv: [real, ...args], env: process.env, cwd: process.cwd() }) + "\n");
});
conn.on("data", (d) => {
  buf += d.toString("utf8");
  for (let i = buf.indexOf("\n"); i >= 0; i = buf.indexOf("\n")) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    let m;
    try { m = JSON.parse(line); } catch { continue; }
    if (m.t === "o") process.stdout.write(Buffer.from(m.d, "base64"));
    else if (m.t === "e") process.stderr.write(Buffer.from(m.d, "base64"));
    else if (m.t === "x") {
      if (m.error) process.stderr.write(`egress-box-shim: ${m.error}\n`);
      code = m.code ?? (m.signal ? 128 + 15 : 255);
    }
  }
});
conn.on("error", (e) => { process.stderr.write(`egress-box-shim: the box's control socket: ${e.message}\n`); process.exit(254); });
conn.on("close", () => process.exit(code));
for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"]) {
  process.on(sig, () => { try { conn.write(JSON.stringify({ op: "kill", signal: sig }) + "\n"); } catch { process.exit(128 + 15); } });
}
