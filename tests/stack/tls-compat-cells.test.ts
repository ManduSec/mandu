/**
 * tls-compat-cells.test — the version- and build-derived expectations of the
 * TLS-inspection compatibility matrix (tests/lib/tls-compat-cells.ts;
 * confidentiality-plan-13-reader-set-labels.md §10.2). Pure: no proxy, no
 * network, no client run.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  cargoLibcurl, cargoNoCainfoCell, cellOf, nodeEnvProxyCell, nodeHonorsEnvProxy,
  parseNodeVersion, transportOnly, wgetCell, wgetTlsBackend,
} from "../lib/tls-compat-cells.js";

test("parseNodeVersion: with or without the v, else null", () => {
  assert.deepEqual(parseNodeVersion("v22.13.0"), [22, 13, 0]);
  assert.deepEqual(parseNodeVersion("24.21.0\n"), [24, 21, 0]);
  assert.equal(parseNodeVersion("node"), null);
  assert.equal(parseNodeVersion(""), null);
});

test("nodeHonorsEnvProxy: fetch from 24.0.0 and 22.21.0", () => {
  for (const v of ["v22.21.0", "v22.22.1", "v24.0.0", "v24.21.0", "v25.0.0", "v26.11.1"]) {
    assert.equal(nodeHonorsEnvProxy(v, "fetch"), true, v);
  }
  // Mandu's floor (22.13.0) and the lines that never had it.
  for (const v of ["v22.13.0", "v22.20.9", "v20.19.0", "v23.11.0", "v18.20.0", "garbage"]) {
    assert.equal(nodeHonorsEnvProxy(v, "fetch"), false, v);
  }
});

test("nodeHonorsEnvProxy: http/https from 24.5.0 and 22.21.0", () => {
  for (const v of ["v22.21.0", "v22.22.1", "v24.5.0", "v24.21.0", "v25.1.0"]) {
    assert.equal(nodeHonorsEnvProxy(v, "https"), true, v);
  }
  for (const v of ["v22.13.0", "v22.20.0", "v23.11.0", "v24.0.0", "v24.4.1"]) {
    assert.equal(nodeHonorsEnvProxy(v, "https"), false, v);
  }
});

test("nodeEnvProxyCell: SERVED where honoured, else BYPASS (never REFUSED)", () => {
  assert.equal(nodeEnvProxyCell("v22.13.0", "fetch"), "BYPASS");
  assert.equal(nodeEnvProxyCell("v22.13.0", "https"), "BYPASS");
  assert.equal(nodeEnvProxyCell("v22.22.1", "fetch"), "SERVED");
  assert.equal(nodeEnvProxyCell("v24.2.0", "fetch"), "SERVED");
  assert.equal(nodeEnvProxyCell("v24.2.0", "https"), "BYPASS");
  assert.equal(nodeEnvProxyCell("v24.21.0", "https"), "SERVED");
});

const WGET_GNUTLS = "GNU Wget 1.25.0 built on linux-gnu.\n\n-cares +digest -gpgme +https +ipv6 +iri +large-file -metalink +nls \n+ntlm +opie +psl +ssl/gnutls \n";
const WGET_OPENSSL = "GNU Wget 1.21.4 built on linux-gnu.\n\n-cares +digest -gpgme +https +ipv6 +iri +large-file -metalink +nls \n+ntlm +opie +psl +ssl/openssl \n";

test("wget: the TLS backend from --version decides the cell", () => {
  assert.equal(wgetTlsBackend(WGET_GNUTLS), "gnutls");
  assert.equal(wgetTlsBackend(WGET_OPENSSL), "openssl");
  assert.equal(wgetCell(WGET_OPENSSL), "SERVED");
  assert.equal(wgetCell(WGET_GNUTLS), "REFUSED");
  assert.equal(wgetCell("GNU Wget 1.25.0 built on linux-gnu.\n-ssl\n"), null);
});

const CARGO_RUSTUP = [
  "cargo 1.75.0 (1d8b05cdd 2023-11-20)", "release: 1.75.0",
  "libgit2: 1.7.1 (sys:0.18.1 vendored)",
  "libcurl: 8.4.0-DEV (sys:0.4.68+curl-8.4.0 vendored ssl:OpenSSL/1.1.1u)",
  "ssl: OpenSSL 1.1.1u  30 May 2023",
].join("\n");
const CARGO_DISTRO_GNUTLS = "cargo 1.75.0\nlibcurl: 8.5.0 (sys:0.4.68+curl-8.4.0 system ssl:GnuTLS/3.8.3)\n";
const CARGO_DISTRO_OPENSSL = "cargo 1.80.1\nlibcurl: 8.9.1 (sys:0.4.73+curl-8.8.0 system ssl:OpenSSL/3.3.1)\n";

test("cargo without CARGO_HTTP_CAINFO: rustup's vendored OpenSSL libcurl is SERVED", () => {
  assert.deepEqual(cargoLibcurl(CARGO_RUSTUP), { vendored: true, backend: "openssl" });
  assert.equal(cargoNoCainfoCell(CARGO_RUSTUP), "SERVED");
});

test("cargo without CARGO_HTTP_CAINFO: a GnuTLS libcurl is REFUSED; other builds are declared build-dependent", () => {
  assert.equal(cargoNoCainfoCell(CARGO_DISTRO_GNUTLS), "REFUSED");
  assert.equal(cargoNoCainfoCell(CARGO_DISTRO_OPENSSL), null);
  assert.equal(cargoNoCainfoCell("cargo 1.75.0\n"), null);
});

test("cellOf / transportOnly: the events a row caused", () => {
  assert.equal(cellOf([]), "BYPASS");
  assert.equal(cellOf(["forwarded"]), "SERVED");
  assert.equal(cellOf(["tls_rejected"]), "REFUSED");
  assert.equal(cellOf(["forward_error", "forwarded"]), "SERVED");
  assert.equal(transportOnly(["forward_error"]), true);
  assert.equal(transportOnly(["forward_error", "forward_error"]), true);
  assert.equal(transportOnly([]), false);
  assert.equal(transportOnly(["tls_rejected", "forward_error"]), false);
});
