/**
 * kube-stream-kind — which requests to a Kubernetes cluster are relayed as
 * streams (docs/design/confidentiality/kube-wire-release.md §4.1), and the
 * heads the relay writes. Pure.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";

import { kubeStreamKind, readResponseHead, streamedResponseHead, withConnection } from "../../src/mitm.js";

test("kubeStreamKind: an HTTP/1.1 upgrade, a watch or a follow; anything else is buffered", () => {
  assert.equal(kubeStreamKind("POST", "/api/v1/namespaces/d/pods/p/exec?command=sh", { Connection: "Upgrade", Upgrade: "SPDY/3.1" }), "upgrade");
  assert.equal(kubeStreamKind("GET", "/api/v1/namespaces/d/pods/p/portforward", { connection: "keep-alive, Upgrade", upgrade: "websocket" }), "upgrade");
  assert.equal(kubeStreamKind("GET", "/x", { connection: "Upgrade" }), null, "no protocol named");
  assert.equal(kubeStreamKind("GET", "/x", { upgrade: "websocket" }), null, "Connection does not ask for it");
  assert.equal(kubeStreamKind("GET", "/api/v1/pods?watch=true&resourceVersion=1", {}), "stream");
  assert.equal(kubeStreamKind("GET", "/api/v1/pods?watch=1", {}), "stream");
  assert.equal(kubeStreamKind("GET", "/api/v1/namespaces/d/pods/p/log?follow=true", {}), "stream");
  assert.equal(kubeStreamKind("GET", "/api/v1/pods?watch=false", {}), null);
  assert.equal(kubeStreamKind("POST", "/api/v1/pods?watch=true", {}), null);
  assert.equal(kubeStreamKind("GET", "/api/v1/pods", {}), null);
});

test("withConnection and streamedResponseHead", () => {
  assert.equal(withConnection("GET / HTTP/1.1\r\nHost: h\r\n\r\n", "Upgrade"), "GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\n\r\n");
  const head = Buffer.from("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n", "latin1");
  assert.equal(streamedResponseHead(head).toString("latin1"), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
});

test("readResponseHead: the head and the bytes after it, across chunks; a close before it or an oversized head rejects", async () => {
  const s = new PassThrough();
  const p = readResponseHead(s, 1024);
  s.write("HTTP/1.1 101 Switching");
  s.write(" Protocols\r\nUpgrade: websocket\r\n\r\nfirst-frame");
  const r = await p;
  assert.equal(r.head.toString(), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n");
  assert.equal(r.rest.toString(), "first-frame");
  assert.ok(s.isPaused(), "left paused for the caller's listener");

  const closed = new PassThrough();
  const q = readResponseHead(closed, 1024);
  closed.end("HTTP/1.1 200");
  await assert.rejects(q, /closed before its response head/);

  const big = new PassThrough();
  const b = readResponseHead(big, 16);
  big.write("HTTP/1.1 200 OK\r\nX-Long: aaaaaaaaaaaaaaaaaaaa");
  await assert.rejects(b, /over 16 bytes/);
});
