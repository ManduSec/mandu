/**
 * credential-names — what a key's NAME says about the value under it, and
 * when a SHORT or simple value under such a name is still a credential
 * (2026-10-19, docs/design/confidentiality/secret-discovery.md §2.9).
 *
 * Three consumers share it, so they agree on what a password's name is:
 *
 *   - the extractor (secret-extract.ts `isSecretKey`): a key named `pw`,
 *     `db_pw`, `passphrase`, `passcode`, `pin` or `access_code` is a secret
 *     key, so a labelled file's twin masks its value as it masks a
 *     `password`'s;
 *   - the catalog's content tier (found-labels.ts `credentialInDataFile`):
 *     a value under a password's or a PIN's name labels the file even when
 *     it is too short or too simple for `looksLikeSecretValue`
 *     (`password = Tr0ub4`, `pin: 4821`), and `auth` is a credential's name
 *     for a long value that reads as a token;
 *   - the value index (prompt-filter/registered-values.ts): a registered
 *     password of 6 or 7 characters is fingerprinted as a WHOLE TOKEN
 *     (`shortTokenValue`), under the general floor of 8 that keeps other
 *     short values out of the tripwire and the value backstop.
 *
 * Tuned for PRECISION: a found label masks a value the model then cannot
 * read, and a short fingerprint that matches by coincidence masks an output
 * or holds a request. Every rule below has a negative row in
 * `credential-names.test.ts`. Pure: no I/O.
 *
 * Mandu-new (no reference origin).
 */
import { isPlaceholder } from "./secret-detectors.js";

/** The words of a key name: split at camelCase and at every character that
 *  is no ASCII letter or digit (`db_pw`, `dbPw`, `DB-PW`, `db.pw`,
 *  `//host/:_password`), lowercased. */
export function keyWords(name: string): string[] {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").split(/[^A-Za-z0-9]+/).filter(Boolean).map((w) => w.toLowerCase());
}

/** The last key name of a field path (`staging.password` → `password`,
 *  `servers.a.args.3` → `args`, `api.example.com.password` → `password`).
 *  Pure. */
export function fieldLastName(field: string): string {
  const segs = field.split(".").filter((s) => s !== "" && !/^\d+$/.test(s));
  return segs[segs.length - 1] ?? "";
}

/** The words that name a password (the last word of the key). */
const PASSWORD_WORDS: ReadonlySet<string> = new Set(["password", "passwd", "pwd", "pw", "pass", "passphrase", "pword"]);

/** A last word that ends in one of these is a password's name too, glued:
 *  `PGPASSWORD`, `dbpassword`, `adminpasswd`. */
const PASSWORD_SUFFIX_RE = /(?:password|passwd|passphrase)$/;

/** `pass` after one of these is a pass of something else (a render pass, a
 *  compiler pass, a first pass), not a password. */
const PASS_NOT_AFTER: ReadonlySet<string> = new Set([
  "first", "second", "third", "last", "final", "multi", "single", "render", "skip", "by", "sub", "post", "pre",
  "one", "two", "num", "n", "max", "min", "high", "low", "band", "all", "boarding", "compile", "build", "lint",
  "shader", "shadow", "depth", "color", "light", "blur", "geometry", "opaque", "transparent", "season", "day",
]);

/** The words before `pin` that make it a PIN (a card's, a phone's, a
 *  door's), not a hardware pin (`led_pin = 17`, `gpio_pin`). */
const PIN_CONTEXT: ReadonlySet<string> = new Set([
  "card", "bank", "atm", "sim", "phone", "mobile", "door", "alarm", "security", "account", "debit", "credit",
  "admin", "user", "safe", "lock", "gate", "garage", "voicemail", "wifi", "wps", "login", "unlock", "master",
  "keypad", "bitlocker", "yubikey", "smartcard", "token", "device", "app", "parental", "entry",
]);

/** `<word>_code` names that are a secret code (`access_code`, a door's or
 *  an alarm's code), not a status or a country code. */
const CODE_CONTEXT: ReadonlySet<string> = new Set([
  "access", "security", "door", "alarm", "gate", "entry", "unlock", "lock", "garage", "safe", "keypad", "pin",
  "pass", "secret", "verification", "backup", "recovery",
]);

/** What kind of secret a key's name says its value is: a `password` (or a
 *  passphrase), a `pin` (a PIN, a passcode, an access code: digits are
 *  enough), or null. `name` is ONE key (the last segment of a field path).
 *  A name ABOUT a password (`password_file`, `password_hint`,
 *  `adminPasswordKey`) ends in another word and is none. Pure. */
export function passwordKind(name: string): "password" | "pin" | null {
  const w = keyWords(name);
  const last = w[w.length - 1];
  if (last === undefined) return null;
  const prev = w.length >= 2 ? w[w.length - 2]! : undefined;
  if (last === "pass") return prev !== undefined && PASS_NOT_AFTER.has(prev) ? null : "password";
  if (PASSWORD_WORDS.has(last) || PASSWORD_SUFFIX_RE.test(last)) return "password";
  if (last === "passcode" || last === "pincode") return "pin";
  if (last === "pin") return prev === undefined || PIN_CONTEXT.has(prev) ? "pin" : null;
  if ((last === "code" || last === "number") && prev === "pin") return "pin";
  if (last === "code" && prev !== undefined && CODE_CONTEXT.has(prev)) return "pin";
  return null;
}

/** Is `name` (one key) `auth` or ends in it (`_auth`, `basic_auth`,
 *  `npmAuth`)? A credential's name only for a value that reads as a token
 *  (found-labels.ts): `auth: basic`, `auth = ldap` are modes. Pure. */
export function authName(name: string): boolean {
  const w = keyWords(name);
  return w[w.length - 1] === "auth";
}

/**
 * Passwords that are the public default of some program, a famous example,
 * or a word that is no password at all (a mode, a hash scheme, a stand-in):
 * under a password's name they say "this is the dev default" or "there is
 * no password here", and masking them costs the model the value and buys
 * nothing (`POSTGRES_PASSWORD: postgres` in a docker-compose file).
 * Compared lowercased; also a listed word followed only by digits or
 * punctuation (`admin123`, `Password1!`, `postgres14`).
 */
const COMMON_PASSWORDS: ReadonlySet<string> = new Set([
  // defaults of databases, brokers and appliances
  "password", "passw0rd", "p@ssw0rd", "p@ssword", "pa55word", "pa$$word", "pass", "passwd", "pwd", "secret", "s3cr3t",
  "changeit", "changeme", "default", "admin", "administrator", "root", "toor", "guest", "user", "users", "test",
  "testing", "tester", "demo", "sample", "dev", "devel", "development", "local", "localhost", "postgres", "postgresql",
  "mysql", "mariadb", "redis", "mongo", "mongodb", "rabbitmq", "oracle", "sa", "sysadmin", "keycloak", "minio",
  "minioadmin", "elastic", "kibana", "grafana", "airflow", "superset", "jenkins", "gitlab", "docker", "vagrant",
  "ubuntu", "raspberry", "alpine", "openstack", "nextcloud", "wordpress", "odoo", "sonar", "nexus", "admin123",
  // the famous examples
  "qwerty", "qwertyuiop", "letmein", "welcome", "monkey", "dragon", "master", "login", "abc123", "abcdef",
  "abcd1234", "iloveyou", "sunshine", "princess", "football", "baseball", "trustno1", "hunter2", "foobar", "foo",
  "bar", "baz", "secret123", "mypassword", "yourpassword", "mysecret",
  // no password: a mode, a scheme, a stand-in
  "none", "null", "nil", "empty", "blank", "nopass", "nopassword", "todo", "fixme", "tbd", "unset", "notset",
  "required", "optional", "hidden", "masked", "prompt", "ask", "keyring", "keychain", "string", "text", "plain",
  "plaintext", "md5", "sha1", "sha256", "sha512", "bcrypt", "argon2", "argon2id", "pbkdf2", "scrypt", "base64",
  "utf8", "true", "false", "yes", "no", "on", "off",
]);

/** Is `v` a public default, a famous example or no password at all
 *  ({@link COMMON_PASSWORDS})? Pure. */
export function commonPassword(v: string): boolean {
  const l = v.toLowerCase();
  if (COMMON_PASSWORDS.has(l)) return true;
  const stem = l.replace(/[^a-z]+$/, "");
  return stem.length >= 3 && stem !== l && COMMON_PASSWORDS.has(stem);
}

/** A run of digits that counts up or down (`123456`, `987654`). Pure. */
function sequentialDigits(v: string): boolean {
  if (!/^\d{3,}$/.test(v)) return false;
  const step = v.charCodeAt(1) - v.charCodeAt(0);
  if (step !== 1 && step !== -1) return false;
  for (let i = 2; i < v.length; i++) if (v.charCodeAt(i) - v.charCodeAt(i - 1) !== step) return false;
  return true;
}

/** A value that NAMES something rather than being a secret, in a form the
 *  long-value tests (`looksLikeSecretValue`, found-labels.ts
 *  `referenceValue`) never see because they take no short value:
 *  lowercase words joined by `-`, `_` or `.` (`scram-sha-256`, `db-creds`,
 *  `vault.db_pw`), an environment variable's name (`DB_PASSWORD`), a
 *  version, an e-mail address, a file name, `host:port`, a YAML alias or
 *  anchor (`*db_pw`), and the template forms of Maven (`@db.pw@`), Windows
 *  (`%DB_PW%`), Azure DevOps (`__DB_PW__`), Ruby and Octopus (`#{db_pw}`),
 *  and Python's `str.format` (`{db_pw}`). Pure. */
export function namesSomething(v: string): boolean {
  return /^[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)+$/.test(v)
    || /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)
    || /^v?\d+(?:\.\d+)+(?:[-+][\w.]+)?$/i.test(v)
    || /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)
    || /^[\w-]+\.(?:txt|key|pem|crt|json|ya?ml|gpg|asc|enc|conf|ini|env|cfg|properties|secret)$/i.test(v)
    || /^[\w.-]+:\d{1,5}$/.test(v)
    || /^[*&][\w.-]+$/.test(v)
    || /^(?:@[\w.-]+@|%[\w.-]+%|__[\w.-]+__|#\{[^}]*\}|\{[\w.]+\})$/.test(v);
}

/**
 * Is `v`, under a name of `kind` ({@link passwordKind}), a credential even
 * though `looksLikeSecretValue` does not take it (too short, or too simple)?
 * The SHORT-VALUE RULE of the content tier (secret-discovery.md §2.9):
 *
 *   - a `pin`: 4 to 12 digits, no run that counts up or down and no one
 *     digit repeated (`1234`, `0000` are stand-ins); or what a password
 *     passes below;
 *   - a `password`: 6 characters or more, no blank, no stand-in
 *     (`isPlaceholder`: `changeme`, `xxxxxx`, `${X}`, `$X`, `<pw>`, `***`),
 *     no public default or famous example ({@link commonPassword}), and
 *     either 6 to 12 digits (no sequence), or a letter together with a
 *     digit or a punctuation mark, that names nothing
 *     ({@link namesSomething}). Letters only stay out: under a password's
 *     name they are a word (`Password`, `Contraseña` in a translation
 *     file), a mode (`keyring`, `prompt`) or an identifier (`dbPassword`).
 *
 * Pure.
 */
export function shortCredentialValue(v: string, kind: "password" | "pin"): boolean {
  if (v.length < 4 || v.length > 128) return false;
  if (/[\s\u0000-\u001f\u007f]/.test(v)) return false;
  if (isPlaceholder(v) || commonPassword(v) || namesSomething(v)) return false;
  if (/^\d+$/.test(v)) return v.length >= (kind === "pin" ? 4 : 6) && v.length <= 12 && !sequentialDigits(v);
  if (v.length < 6) return false;
  if (!/\p{L}/u.test(v)) return false; // digits and punctuation: a date, an address, a phone number
  return /\p{N}/u.test(v) || /[^\p{L}\p{N}]/u.test(v);
}

/**
 * The SHORT-FINGERPRINT RULE (secret-discovery.md §2.9, "The tripwire"):
 * may a registered password value shorter than the general floor of 8
 * characters (egress-fingerprint.ts MIN_FINGERPRINT_LEN) be fingerprinted
 * on its own, matched only as a whole token ({@link tokenBounded})? Only a
 * value of 6 or 7 characters that {@link shortCredentialValue} takes as a
 * password and that holds a letter: a digits-only value (a PIN, a 6-digit
 * code) is a number every body may hold by chance, and is left to the
 * symbol gates. The caller decides the row is a password's (a registered
 * file's field under a password's name, or a password variable's row).
 * Pure.
 */
export const MIN_SHORT_TOKEN_LEN = 6;
export function shortTokenValue(v: string, floor: number): boolean {
  return v.length >= MIN_SHORT_TOKEN_LEN && v.length < floor && /\p{L}/u.test(v) && shortCredentialValue(v, "password");
}

/** A letter or a digit (any script). */
function wordChar(c: string | undefined): boolean {
  return c !== undefined && /[\p{L}\p{N}]/u.test(c);
}

/** Does the occurrence of `value` at [start, end) of `text` stand as a
 *  whole token: no letter or digit glued to an end of it that is itself a
 *  letter or digit (`pw=Tr0ub4;` and `"Tr0ub4"` match, `xTr0ub4` and
 *  `Tr0ub4z` do not; a value that ends in `!` takes any character after
 *  it). The text's own ends are token ends. Pure. */
export function tokenBounded(text: string, start: number, end: number, value: string): boolean {
  if (wordChar(value[0]) && wordChar(text[start - 1])) return false;
  if (wordChar(value[value.length - 1]) && wordChar(text[end])) return false;
  return true;
}

/** Does `value` occur in `text` as a whole token anywhere? Pure. */
export function tokenOccurs(text: string, value: string): boolean {
  if (value === "") return false;
  for (let i = text.indexOf(value); i !== -1; i = text.indexOf(value, i + 1)) {
    if (tokenBounded(text, i, i + value.length, value)) return true;
  }
  return false;
}
