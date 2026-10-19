/**
 * credential-names — a password's or a PIN's name, the short-value rule of
 * the catalog's content tier, and the short-token rule of the value index
 * and the egress tripwire (2026-10-19, secret-discovery.md §2.9).
 *
 * Every positive row has a negative beside it: a found label masks a value
 * the model then cannot read, and a short fingerprint that matches by
 * coincidence masks an output or holds a request.
 *
 * Confidentiality axis: what the content tier labels and what the value
 * backstop and the tripwire match.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  authName, commonPassword, fieldLastName, namesSomething, passwordKind, shortCredentialValue, shortTokenValue, tokenBounded, tokenOccurs,
} from "../../policy/credential-names.js";
import { MIN_FINGERPRINT_LEN, scanEgressFingerprint, type SecretFingerprint } from "../../policy/egress-fingerprint.js";
import { RegisteredValueIndex, scanEgressFingerprintIndexed, shortTokenRow } from "../../prompt-filter/registered-values.js";
import type { SymbolEntry, SymbolMap } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

test("passwordKind: a password's and a PIN's names, glued or split, never a name ABOUT one or a pin of hardware", () => {
  for (const n of ["password", "PASSWORD", "passwd", "pwd", "pw", "PW", "db_pw", "dbPw", "DB-PW", "pass", "SMTP_PASS", "smtpPass", "db_pass", "PGPASSWORD", "adminpassword", "MYSQL_PWD", "passphrase", "keyPassphrase", "ossrhPassword", "_password"]) {
    assert.equal(passwordKind(n), "password", n);
  }
  for (const n of ["pin", "PIN", "card_pin", "cardPin", "door_pin", "pin_code", "pincode", "passcode", "access_code", "accessCode", "alarm_code", "door_code", "security_code"]) {
    assert.equal(passwordKind(n), "pin", n);
  }
  for (const n of [
    "password_file", "passwordFile", "password_hint", "adminPasswordKey", "pw_hash", "pwd_dir", "passwordless",      // about a password
    "first_pass", "render_pass", "shadow_pass", "bypass", "compass", "passenger",                                   // a pass of something else
    "led_pin", "gpio_pin", "reset_pin", "pin_mode", "pins", "spinner", "mapping",                                   // hardware, or another word
    "status_code", "country_code", "zip_code", "code", "error_code", "user", "name", "port", "host", "token", "",
  ]) {
    assert.equal(passwordKind(n), null, n);
  }
  assert.ok(authName("auth") && authName("_auth") && authName("basic_auth") && authName("npmAuth"));
  assert.ok(!authName("oauth") && !authName("auth_type") && !authName("author"));
  assert.equal(fieldLastName("api.example.com.password"), "password");
  assert.equal(fieldLastName("servers.a.args.3"), "args");
});

test("shortCredentialValue: a short or simple password or PIN, never a default, a stand-in, a word, a mode or a name", () => {
  for (const v of ["Tr0ub4", "k9z!q2", "S3cret-77", "x7#Lq9", "dbProd2026", "Garden!Lamp", "834291", "q2W3e4"]) {
    assert.ok(shortCredentialValue(v, "password"), v);
  }
  for (const v of ["4821", "90210", "77341298"]) assert.ok(shortCredentialValue(v, "pin"), `pin ${v}`);
  for (const v of [
    "", "abc12", "Tr0b",                                                                    // too short
    "postgres", "hunter2", "changeit", "admin123", "Password1!", "postgres14", "Secret!", "abc123", "123456", "qwerty", // a default, a famous example
    "changeme", "xxxxxx", "${DB_PASSWORD}", "$DB_PW", "<password>", "******", "%(pw)s", "{{ pw }}",                       // a stand-in or a reference
    "Password", "Contraseña", "Passwort", "keyring", "prompt", "required", "dbPassword", "sunshine", "PASSWORD",         // letters only: a word, a mode, a name
    "DB_PASSWORD", "scram-sha-256", "db-creds", "vault.db_pw", "v1.2.3", "1.2.3", "me@mail.test", "secret.txt",         // names something
    "db.internal:5432", "*db_pw", "&pw", "@db.password@", "%DB_PW%", "__DB_PW__", "#{db_pw}", "{db_pw}",
    "2024-01-01", "10.0.0.1", "+1-555-0100",                                                 // digits and marks only
    "123456789", "987654", "with space1", "tab\there1",                                     // a sequence; a blank
  ]) {
    assert.ok(!shortCredentialValue(v, "password"), JSON.stringify(v));
  }
  for (const v of ["1234", "0000", "17", "123", "abcd"]) assert.ok(!shortCredentialValue(v, "pin"), `pin ${v}`);
  assert.ok(commonPassword("ROOT") && commonPassword("Root#2024") && !commonPassword("Tr0ub4"));
  assert.ok(namesSomething("DB_PASSWORD") && !namesSomething("Tr0ub4"));
});

test("shortTokenValue and tokenBounded: 6 or 7 characters with a letter, as a whole token only", () => {
  assert.ok(shortTokenValue("Tr0ub4", MIN_FINGERPRINT_LEN) && shortTokenValue("k9z!q2x", MIN_FINGERPRINT_LEN));
  for (const v of ["834291", "Tr0ub4dor", "Tr0b4", "hunter2", "Password"]) assert.ok(!shortTokenValue(v, MIN_FINGERPRINT_LEN), v);
  const v = "Tr0ub4";
  for (const t of [v, `pw=${v}`, `"${v}"`, `${v};`, `user:${v}@host`, `x ${v}\n`, `a_${v}_b`]) assert.ok(tokenOccurs(t, v), t);
  for (const t of [`x${v}`, `${v}z`, `${v}9`, `Tr0ub4Tr0ub45`, "Tr0ub"]) assert.ok(!tokenOccurs(t, v), t);
  // a value that ends in a mark takes any character after it
  assert.ok(tokenOccurs("k9z!q2!abc", "k9z!q2!"));
  assert.ok(tokenBounded("ab", 0, 2, "ab") && !tokenBounded("xab", 1, 3, "ab"));
});

// ── the value index and the tripwire ────────────────────────────────────────

function row(value: string, field: string | null, over: Partial<SymbolEntry> = {}): SymbolEntry {
  return {
    value, tool: "Read", field, origin: "/w/config.ini", session_key: null, call_id: null, created_at: 0,
    obsoleted_at: null, obsoleted_by: null, derived_from: null, line_range: null,
    confidentiality: "no-model", bindings: null, integrity: "trusted", ...over,
  };
}

const PW = "Tr0ub4";
const ROWS: Array<[string, SymbolEntry]> = [
  ["$MDU:nomodel_Read[a1].database.password", row(PW, "database.password")],
  ["$MDU:nomodel_Read[a1].card_pin", row("4821", "card_pin")],                       // digits: no fingerprint
  ["$MDU:nomodel_Read[a1].database.user", row("appusr", "database.user")],          // not a password's field
  ["$MDU:nomodel_Env[e2].PGPASSWORD", row("k9z!q2x", null, { tool: "Env", origin: "env:PGPASSWORD" })],
  ["$MDU:nomodel_Bash[c3]", row("Zq7v2X", null, { tool: "Bash", call_id: "c3", origin: null, integrity: "untrusted" })], // an output row
];

test("shortTokenRow: a registered file's password field or a password variable, 6 or 7 characters; nothing else", () => {
  const got = ROWS.map(([n, e]) => [n, shortTokenRow(e)]);
  assert.deepEqual(got, [
    ["$MDU:nomodel_Read[a1].database.password", true],
    ["$MDU:nomodel_Read[a1].card_pin", false],
    ["$MDU:nomodel_Read[a1].database.user", false],
    ["$MDU:nomodel_Env[e2].PGPASSWORD", true],
    ["$MDU:nomodel_Bash[c3]", false],
  ]);
  assert.equal(shortTokenRow(row("Tr0ub4dor&3", "password")), false, "at or above the floor: the general rule");
  assert.equal(shortTokenRow(row("hunter2", "password")), false, "a famous example");
});

test("the index matches a short password as a whole token in hits, occurrences and the stream, and the tripwire trips on it (the reference agrees)", () => {
  const map: SymbolMap = { symbols: new Map(ROWS) };
  const idx = new RegisteredValueIndex();
  idx.sync(map);
  assert.ok(idx.isTokenRow("$MDU:nomodel_Read[a1].database.password") && idx.isTokenRow("$MDU:nomodel_Env[e2].PGPASSWORD"));
  assert.ok(!idx.isTokenRow("$MDU:nomodel_Read[a1].card_pin"));
  const pwName = "$MDU:nomodel_Read[a1].database.password";

  assert.deepEqual(idx.hits(`psql "password=${PW} host=db"`), [{ symbol: pwName, how: "value" }]);
  assert.deepEqual(idx.hits(`id x${PW}y and 4821 and appusr`), [], "glued: no token; a PIN and a short non-password: no fingerprint");
  const occ = idx.occurrences(`a ${PW} b x${PW} c ${PW}`);
  assert.deepEqual(occ.map((o) => [o.symbol, o.start]), [[pwName, 2], [pwName, 21]]);

  // the stream answers what hits() answers over the joined text, at every split
  for (const text of [`pw=${PW};`, `pw=${PW}z`, `zz${PW}`, `${PW}`, `xx${PW}`, `${PW}9 ok`, `-- k9z!q2xx -- k9z!q2x`]) {
    const want = idx.hits(text).map((h) => h.symbol);
    for (let cut = 0; cut <= text.length; cut++) {
      for (let cut2 = cut; cut2 <= text.length; cut2 += 3) {
        const s = idx.stream();
        s.push(text.slice(0, cut));
        s.push(text.slice(cut, cut2));
        s.push(text.slice(cut2));
        assert.deepEqual(s.hits().map((h) => h.symbol), want, `${JSON.stringify(text)} cut at ${cut}/${cut2}`);
      }
    }
  }

  // the tripwire: indexed, and the pure reference with `token`
  const fp = (name: string): SecretFingerprint | null => {
    const e = map.symbols.get(name);
    return e ? { symbol: name, value: e.value, level: e.confidentiality, bindings: [], token: shortTokenRow(e) } : null;
  };
  const secrets = ROWS.map(([n]) => fp(n)!);
  for (const [body, want] of [
    [`{"db":{"password":"${PW}"}}`, [pwName]],
    [`login=admin&pass=k9z!q2x`, ["$MDU:nomodel_Env[e2].PGPASSWORD"]],
    [`{"id":"x${PW}y","pin":"4821","user":"appusr"}`, []],
  ] as const) {
    const surfaces = [{ where: "body", text: body }];
    assert.deepEqual(scanEgressFingerprintIndexed(surfaces, idx, fp, "paste.example").map((h) => h.symbol), want, body);
    assert.deepEqual(scanEgressFingerprint(surfaces, secrets, "paste.example").map((h) => h.symbol), want, `reference: ${body}`);
  }
  // a reference fingerprint WITHOUT `token` keeps the floor (any other short value)
  assert.deepEqual(scanEgressFingerprint([{ where: "body", text: PW }], [{ ...fp(pwName)!, token: false }], "paste.example"), []);
});
