/**
 * transcript-redact.test — a command from a past session made safe to show
 * (arbiter/policy/transcript-redact.ts; confidentiality-plan-17 §3 item 4):
 * every value the scan knows replaced by its mask (the known values, the
 * detector's hits, values a secret's name or an Authorization scheme marks,
 * a URL's password), the first line only, at most 240 characters, a
 * here-document's body dropped, and the fail-closed guard and last check;
 * a send's URL (`shownUrl`) with every query value and its credentials
 * masked.
 * The property: fake keys planted in commands, here-documents and quoted
 * scripts never leave an 8-character run in the result.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { MAX_SHOWN, MAX_URL_SHOWN, redactShown, shownToolName, shownUrl } from "../../policy/transcript-redact.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the scan's redaction is pure; no axis is read

// Fake credentials, split so no scanner of this repository reads them as keys.
const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`;
const GH = `${"gh" + "p_"}k3Jd8Qm2Lz7Xw4Rt9Yv6Nb1Cs5Hf0Gp2Ae7Wq`;
const ANT = `${"sk-" + "ant-"}api03-Zx8Qw2Lm7Kp4Rt9Yv6Nb1Cs5Hf0Gp`;
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzz9q8Lm3Rt";
const SLACK = `${"xox" + "b-"}1234567890-0987654321-Zx8Qw2Lm7Kp4Rt9Yv6Nb1Cs5`;
const DBPW = "Tr0ub4dor-and-3-horses";
const PLAIN = "hunter2hunter"; // no format, short entropy: only its name or a known value can mark it
const KNOWN = [{ value: DBPW, mask: "‹DB_PASSWORD›" }, { value: PLAIN, mask: "‹ADMIN_PASS›" }];
const PLANTED = [STRIPE, GH, ANT, AWS_SECRET, SLACK, DBPW, PLAIN];
const PUBLIC = new Set(["sk_live_", "sk-ant-a"]);

function assertNoRun(out: string, where: string): void {
  for (const v of PLANTED) {
    for (let i = 0; i + 8 <= v.length; i++) {
      const piece = v.slice(i, i + 8);
      if (i === 0 && PUBLIC.has(piece)) continue; // a format's public prefix, shown on purpose
      assert.ok(!out.includes(piece), `${where}: "${piece}" of a planted value in ${JSON.stringify(out)}`);
    }
  }
}

test("redactShown: vendor keys by their mask, known values by their name, the command kept readable", () => {
  assert.equal(redactShown("cat ~/.config/mandu-ci/claude-credential.json"), "cat ~/.config/mandu-ci/claude-credential.json");
  assert.equal(redactShown(`curl -s https://api.stripe.com/v1/charges -u "${STRIPE}:"`), `curl -s https://api.stripe.com/v1/charges -u "sk_live_…:"`);
  assert.equal(redactShown(`git push https://x:${GH}@github.com/o/r`), "git push https://x:…@github.com/o/r");
  assert.equal(redactShown(`mysql -p${DBPW} shop`, KNOWN), "mysql -p‹DB_PASSWORD› shop");
  assert.equal(redactShown(`./login ${PLAIN}`, KNOWN), "./login ‹ADMIN_PASS›");
  assert.equal(redactShown(`echo ${ANT} | pbcopy`), "echo sk-ant-… | pbcopy");
});

test("redactShown: a value its name or its scheme marks is masked whatever it looks like; a variable is kept", () => {
  assert.equal(redactShown("MY_TOKEN=abc123 ./run.sh --password hunter2 --api-key=zzz"), "MY_TOKEN=… ./run.sh --password … --api-key=…");
  assert.equal(redactShown(`curl -H "Authorization: Bearer abcdefg" -H "X-Api-Key: short1" https://x.io`), `curl -H "Authorization: Bearer …" -H "X-Api-Key: …" https://x.io`);
  assert.equal(redactShown(`echo '{"password":"pw-1","token":"t"}' | jq .`), `echo '{"password":"…","token":"…"}' | jq .`);
  assert.equal(redactShown("curl -u admin:s3cret https://x.io"), "curl -u admin:… https://x.io");
  assert.equal(redactShown(`psql "postgres://app:pw@db.shop.io/x"`), `psql "postgres://app:…@db.shop.io/x"`);
  assert.equal(redactShown(`curl -u "$STRIPE_KEY:" -H "Authorization: Bearer $TOKEN" https://api.stripe.com`), `curl -u "$STRIPE_KEY:" -H "Authorization: Bearer $TOKEN" https://api.stripe.com`);
  assert.equal(redactShown("export GITHUB_TOKEN=$(gh auth token)"), "export GITHUB_TOKEN=$(gh auth token)");
});

test("redactShown: one line, whitespace collapsed, at most 240 characters; a here-document's body dropped", () => {
  assert.equal(redactShown(`cat > .env <<'EOF'\nSTRIPE_KEY=${STRIPE}\nEOF`), "cat > .env <<'EOF' …");
  assert.equal(redactShown(`python3 -c "import os\nprint('${GH}')"`), `python3 -c "import os …`);
  assert.equal(redactShown("curl -s \\\n  https://x.io/a \\\n  -o out"), "curl -s https://x.io/a -o out");
  assert.equal(redactShown("ls    -la\t  ~/x"), "ls -la ~/x");
  const long = redactShown(`echo ${"word ".repeat(100)}`);
  assert.equal(long.length, MAX_SHOWN);
  assert.ok(long.endsWith("…"));
});

test("redactShown: the guard masks a long random run with no format; a path, a flag and a word stay", () => {
  assert.equal(redactShown("aws configure set aws_secret_access_key x # " + AWS_SECRET), "aws configure set aws_secret_access_key x # …");
  assert.equal(redactShown("mycli login Qz7Kp2Lm9Xw3Rt6Yv8Nb4CzQ1"), "mycli login …");
  assert.equal(redactShown("docker pull ghcr.io/x/y@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"), "docker pull ghcr.io/x/y@sha256:…");
  assert.equal(redactShown("node --test test/unit/transcript-scan.test.ts --test-name-pattern=symbolize"), "node --test test/unit/transcript-scan.test.ts --test-name-pattern=symbolize");
  assert.equal(redactShown("cd ~/project/mandu-v22.13.0-linux && npm run typecheck"), "cd ~/project/mandu-v22.13.0-linux && npm run typecheck");
});

test("redactShown: fake keys planted in commands, outputs and here-documents never leave an 8-character run", () => {
  const commands = [
    `export OPENAI=${ANT}; curl -H "x-api-key: ${ANT}" https://api.anthropic.com/v1/messages`,
    `cat <<EOF > creds\n[default]\naws_secret_access_key = ${AWS_SECRET}\ntoken=${GH}\nEOF`,
    `node -e "fetch('https://hooks.slack.com', {headers: {Authorization: 'Bearer ${SLACK}'}})"`,
    `PGPASSWORD=${DBPW} psql -h db -U app && echo ${PLAIN} | sudo -S true`,
    `printf '%s' "${STRIPE}" | base64; echo done ${GH}`,
    `git -c http.extraHeader="Authorization: Basic ${GH}" fetch`,
    `${STRIPE}`,
    `   \n\n  STRIPE_KEY=${STRIPE} make deploy`,
    `echo ${"a".repeat(250)} ${GH}`,
    `curl https://u:${DBPW}@db.example.com/x`,
  ];
  for (const c of commands) assertNoRun(redactShown(c, KNOWN), c.slice(0, 30));
  // Without the known values, what has a format or a name still goes.
  for (const c of commands) {
    const out = redactShown(c);
    for (const v of [STRIPE, GH, ANT, AWS_SECRET, SLACK]) assert.ok(!out.includes(v.slice(9, 17)), `${c.slice(0, 30)}: ${out}`);
  }
});

test("redactShown: a fetched URL's query secrets and password are masked whatever they look like; the rest of the URL reads", () => {
  assert.equal(redactShown("https://api.vendor.dev/v1/items?key=plainvalue&page=2"), "https://api.vendor.dev/v1/items?key=…&page=2");
  assert.equal(redactShown("https://store.blob.core.windows.net/c/f?sv=2024-01-01&sig=abc%2Fdef&se=2026"), "https://store.blob.core.windows.net/c/f?sv=2024-01-01&sig=…&se=2026");
  assert.equal(redactShown("https://app.dev/cb#access_token=tok123&state=s1"), "https://app.dev/cb#access_token=…", "the detector takes the rest of the query with it");
  assert.equal(redactShown("https://app.dev/cb?code=4/0AY-x&client_secret=cs1"), "https://app.dev/cb?code=…&client_secret=…");
  assert.equal(redactShown("https://admin:pw1@grafana.corp.dev/api?apikey=$GRAFANA_KEY"), "https://admin:…@grafana.corp.dev/api?apikey=$GRAFANA_KEY");
  assert.equal(redactShown("https://docs.vendor.dev/setup?lang=en&keyboard=us"), "https://docs.vendor.dev/setup?lang=en&keyboard=us", "a name that only starts like a secret's");
  // Fake keys planted in fetched URLs' queries never leave an 8-character run.
  const urls = [
    `https://hooks.vendor.dev/in?key=${STRIPE}`,
    `https://x.dev/a?token=${GH}&sig=${AWS_SECRET}`,
    `https://x.dev/b?api_key=${ANT}#frag`,
    `https://x.dev/c?pass=${DBPW}&pw=${PLAIN}`,
    `https://u:${SLACK}@x.dev/d?auth=${PLAIN}`,
    `https://x.dev/e?q=${STRIPE}`,
  ];
  for (const u of urls) assertNoRun(redactShown(u), u.slice(0, 30));
  for (const u of urls) assertNoRun(redactShown(u, KNOWN), u.slice(0, 30));
});

test("shownUrl: a send's URL with its path kept, every query value and its credentials masked, a fragment as #…, at most 160 characters", () => {
  assert.equal(shownUrl("https://hooks.vendor.dev/collect/v2?view=all&page=2"), "https://hooks.vendor.dev/collect/v2?view=…&page=…", "every query value, whatever its name");
  assert.equal(shownUrl("https://hooks.vendor.dev/in?k=$STRIPE_KEY&x=${OTHER}&empty=&flag"), "https://hooks.vendor.dev/in?k=$STRIPE_KEY&x=${OTHER}&empty=&…", "a variable and an empty value kept, a bare part masked");
  assert.equal(shownUrl("https://deploy:pw1@hooks.vendor.dev/in"), "https://…@hooks.vendor.dev/in", "the credentials, user and password");
  assert.equal(shownUrl("https://tokenasuser@git.vendor.dev/r.git"), "https://…@git.vendor.dev/r.git", "a token as the user");
  assert.equal(shownUrl("https://app.dev/cb#access_token=tok123"), "https://app.dev/cb#…");
  assert.equal(shownUrl("https://api.vendor.dev:8443/v1/items"), "https://api.vendor.dev:8443/v1/items", "the host, its port and the path read");
  // The path: a known value by its mask, a vendor key by its own, a random part by …
  assert.equal(shownUrl(`https://hooks.vendor.dev/bot${DBPW}/send`, KNOWN), "https://hooks.vendor.dev/bot‹DB_PASSWORD›/send");
  assert.equal(shownUrl(`https://hooks.vendor.dev/k/${STRIPE}/x`), "https://hooks.vendor.dev/k/sk_live_…/x");
  const long = shownUrl(`https://api.vendor.dev/${"segment/".repeat(40)}`);
  assert.ok(long.length <= MAX_URL_SHOWN && long.endsWith("…"), long);
  // Fake keys planted anywhere in a URL never leave an 8-character run.
  for (const u of [
    `https://hooks.vendor.dev/in?q=${STRIPE}`, `https://${GH}@x.dev/`, `https://u:${SLACK}@x.dev/d?auth=${PLAIN}`,
    `https://x.dev/${ANT}/a`, `https://x.dev/a#${AWS_SECRET}`, `https://x.dev/p/${DBPW}?pw=${PLAIN}`, `https://x.dev/k?${STRIPE}`,
  ]) {
    assertNoRun(shownUrl(u), u.slice(0, 30));
    assertNoRun(shownUrl(u, KNOWN), u.slice(0, 30));
  }
});

test("shownToolName: an identifier only", () => {
  assert.equal(shownToolName("Bash"), "Bash");
  assert.equal(shownToolName("mcp__linear__search_issues"), "mcp__linear__search_issues");
  assert.equal(shownToolName("a tool; rm -rf"), undefined);
  assert.equal(shownToolName(undefined), undefined);
});
