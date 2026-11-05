/**
 * The confined-commands box's pure parts (docs/design/agents/openclaw-plugin.md
 * §10): the frame codec both sides speak, the command environment the box
 * composes, the argv a command runs under, the root check, and the facts that
 * decide whether a box is confined enough to use (fail closed).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CHUNK, FrameDecoder, MAX_FRAME, T, chunkFrames, encodeFrame, frameJson } from "../../box/frames.mjs";
import { boxFactsProblems, commandArgv, isInside, mergeCommandEnv } from "../../box/policy.mjs";

test("frames: encode then decode, split anywhere, keeps type and bytes", () => {
  const frames = [
    encodeFrame(T.REQUEST, { op: "run", ticket: "abc" }),
    encodeFrame(T.STDOUT, Buffer.from([0, 1, 2, 255])),
    encodeFrame(T.STDIN_END),
    encodeFrame(T.STDERR, "héllo"),
  ];
  const wire = Buffer.concat(frames);
  for (let cut = 0; cut <= wire.length; cut++) {
    const d = new FrameDecoder();
    const got = [...d.push(wire.subarray(0, cut)), ...d.push(wire.subarray(cut))];
    assert.equal(got.length, 4);
    assert.deepEqual(got.map((f) => f.type), ["Q", "O", "E", "e"]);
    assert.deepEqual(frameJson(got[0]!.payload), { op: "run", ticket: "abc" });
    assert.deepEqual([...got[1]!.payload], [0, 1, 2, 255]);
    assert.equal(got[2]!.payload.length, 0);
    assert.equal(got[3]!.payload.toString("utf8"), "héllo");
  }
});

test("frames: an unknown type or an oversized frame is an error, never a frame", () => {
  assert.throws(() => encodeFrame("Z", "x"), /unknown frame type/);
  const bad = Buffer.from([0x5a, 0, 0, 0, 1, 0x41]);
  assert.throws(() => new FrameDecoder().push(bad), /unknown frame type/);
  const big = Buffer.alloc(5);
  big.write("O", 0, 1, "latin1");
  big.writeUInt32BE(MAX_FRAME + 1, 1);
  assert.throws(() => new FrameDecoder().push(big), /over/);
  assert.equal(frameJson(Buffer.from("not json")), null);
});

test("frames: chunkFrames cuts a large payload into CHUNK-sized frames", () => {
  const data = Buffer.alloc(CHUNK * 2 + 7, 0x61);
  const out = chunkFrames(T.STDIN, data);
  assert.equal(out.length, 3);
  const back = new FrameDecoder().push(Buffer.concat(out));
  assert.equal(Buffer.concat(back.map((f) => f.payload)).equals(data), true);
});

test("env: the launch's protected variables, Mandu's own and masked ones win; the request adds the rest", () => {
  const base = {
    PATH: "/mandu/shims:/usr/bin",
    HTTPS_PROXY: "http://127.0.0.1:4000",
    MANDU_NET_GUARD_PROXY_PORTS: "4000",
    GITHUB_TOKEN: "$MDU:nomodel_Env[ab12]",
    HOME: "/home/u",
    LANG: "C",
  };
  const env = mergeCommandEnv(base, {
    PATH: "/usr/bin:/opt/tools/bin",
    HTTPS_PROXY: "",
    https_proxy: "http://evil:1",
    MANDU_NET_GUARD_PROXY_PORTS: "1",
    MANDU_EXTRA: "x",
    GITHUB_TOKEN: "ghp_realvalue",
    HOME: "/workspace",
    LANG: "C.UTF-8",
    OPENCLAW_SHELL: "1",
    "BAD-NAME": "x",
    NUM: 3 as unknown as string,
  });
  assert.equal(env["PATH"], "/mandu/shims:/usr/bin:/opt/tools/bin", "the box's PATH first, the request's new directories after");
  assert.equal(env["HTTPS_PROXY"], "http://127.0.0.1:4000");
  assert.equal(env["https_proxy"], "http://evil:1", "a proxy name the box does not set may be added (the guard still allows only the proxy)");
  assert.equal(env["MANDU_NET_GUARD_PROXY_PORTS"], "4000");
  assert.equal(env["MANDU_EXTRA"], undefined, "no MANDU_* name comes from the request");
  assert.equal(env["GITHUB_TOKEN"], "$MDU:nomodel_Env[ab12]", "a variable the launch masked stays masked");
  assert.equal(env["HOME"], "/home/u", "the user's HOME, not OpenClaw's container-style workspace HOME");
  assert.equal(env["LANG"], "C.UTF-8");
  assert.equal(env["OPENCLAW_SHELL"], "1");
  assert.equal(env["BAD-NAME"], undefined);
  assert.equal(env["NUM"], undefined);
});

test("argv: sh -c, or under script(1) when a terminal was asked and script exists", () => {
  assert.deepEqual(commandArgv("ls -l", false, "/usr/bin/script"), ["/bin/sh", "-c", "ls -l"]);
  assert.deepEqual(commandArgv("vim", true, "/usr/bin/script"), ["/usr/bin/script", "-qfec", "vim", "/dev/null"]);
  assert.deepEqual(commandArgv("vim", true, null), ["/bin/sh", "-c", "vim"]);
});

test("roots: inside is at or under, never a sibling with the same prefix", () => {
  assert.equal(isInside("/w", "/w"), true);
  assert.equal(isInside("/w", "/w/a/b"), true);
  assert.equal(isInside("/w/", "/w/a"), true);
  assert.equal(isInside("/w", "/wx"), false);
  assert.equal(isInside("/w", "/"), false);
  assert.equal(isInside("/", "/anything"), true);
});

test("facts: a box is used only with the guard, its proxy and Mandu's folder hidden (fail closed)", () => {
  assert.deepEqual(boxFactsProblems({ seccomp: "2", manduHome: "hidden", egressProxy: true, guardPorts: true }), []);
  assert.deepEqual(boxFactsProblems({ seccomp: "2", manduHome: "absent", egressProxy: true, guardPorts: true }), []);
  assert.equal(boxFactsProblems(null).length, 1);
  assert.match(boxFactsProblems({ seccomp: "0", manduHome: "hidden", egressProxy: true, guardPorts: true }).join(), /network guard/);
  assert.match(boxFactsProblems({ seccomp: "2", manduHome: "visible", egressProxy: true, guardPorts: true }).join(), /Mandu's own folder/);
  assert.match(boxFactsProblems({ seccomp: "2", manduHome: "hidden", egressProxy: false, guardPorts: true }).join(), /egress proxy/);
  assert.match(boxFactsProblems({ seccomp: "2", manduHome: "hidden", egressProxy: true, guardPorts: false }).join(), /does not name/);
});
