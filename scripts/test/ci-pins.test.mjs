// ci-pins.test.mjs — scripts/ci/pins.env is the one list of versions the CI
// image is built from (docs/design/testing/continuous-integration.md §4). The hand-run
// docker rig (packaging/docker/Dockerfile.ci) keeps its own ARG defaults and
// GitHub CI (.github/workflows/ci.yml) its own node/rust floor: this fails
// when any of them drifts from pins.env. Offline: reads three files.
//
// Run: node --test scripts/test/ci-pins.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const read = (p) => fs.readFileSync(path.join(REPO, p), "utf8");

/** pins.env as the guest and vm-image.sh read it: KEY=value, no expansion. */
export function parsePins(text) {
  const pins = {};
  for (const [i, line] of text.split("\n").entries()) {
    if (/^\s*(#|$)/.test(line)) continue;
    const m = /^([A-Z][A-Z0-9_]*)=([A-Za-z0-9._:/+-]*)$/.exec(line);
    if (!m) throw new Error(`pins.env line ${i + 1} is not KEY=value in the allowed charset: ${line}`);
    if (m[1] in pins) throw new Error(`pins.env sets ${m[1]} twice`);
    pins[m[1]] = m[2];
  }
  return pins;
}

const pins = parsePins(read("scripts/ci/pins.env"));

test("pins.env: every line is KEY=value in the charset ci_read_pins accepts, and the expected keys are set", () => {
  for (const k of ["NODE_VERSION", "RUST_VERSION", "CLAUDE_CODE_VERSION", "CODEX_VERSION", "OPENCODE_VERSION",
    "OPENCODE2_VERSION", "OPENCLAW_VERSION", "UBUNTU_CLOUD_BASE", "UBUNTU_CLOUD_RELEASE", "UBUNTU_CLOUD_IMAGE", "UBUNTU_APT_MIRROR",
    "BWRAP_VERSION", "BWRAP_SHA256"]) {
    assert.ok(pins[k], `pins.env lacks ${k}`);
  }
  assert.match(pins.BWRAP_SHA256, /^[0-9a-f]{64}$/);
  assert.match(pins.UBUNTU_CLOUD_RELEASE, /^release-\d{8}$/, "a dated (immutable) cloud-image release");
  assert.match(pins.UBUNTU_CLOUD_BASE, /^https:\/\//);
  assert.match(pins.UBUNTU_APT_MIRROR, /^https?:\/\/[a-z0-9.-]+(\/[a-z0-9._-]+)*\/ubuntu$/,
    "an Ubuntu archive mirror URL, no trailing slash (provision.sh appends one)");
  const [maj, min] = pins.BWRAP_VERSION.split(".").map(Number);
  assert.ok(maj > 0 || min >= 10, "ns-run.sh's overlay needs bubblewrap >= 0.10");
});

test("pins.env: each CI guest (lib.sh CI_GUESTS) has its dated base-image pins, 26.04 the resolute release", () => {
  const lib = read("scripts/ci/lib.sh");
  const guests = /^CI_GUESTS="([^"]+)"$/m.exec(lib)[1].split(/\s+/);
  assert.deepEqual(guests, ["ubuntu-2404", "ubuntu-2604"]);
  // ci_pins_prefix: ubuntu-2404 -> UBUNTU_, ubuntu-2604 -> UBUNTU_2604_.
  for (const [guest, pfx, image] of [["ubuntu-2404", "UBUNTU_", /^ubuntu-24\.04-server-cloudimg-amd64\.img$/],
    ["ubuntu-2604", "UBUNTU_2604_", /^ubuntu-26\.04-server-cloudimg-amd64\.img$/]]) {
    assert.ok(lib.includes(`${guest}) echo ${pfx} ;;`), `lib.sh maps ${guest} to ${pfx}`);
    assert.match(pins[`${pfx}CLOUD_RELEASE`], /^release-\d{8}$/, `${guest}: a dated (immutable) release`);
    assert.match(pins[`${pfx}CLOUD_BASE`], /^https:\/\/cloud-images\.ubuntu\.com\/releases\/[a-z]+$/, `${guest}: base URL`);
    assert.match(pins[`${pfx}CLOUD_IMAGE`], image, `${guest}: the amd64 server cloud image`);
  }
  assert.match(pins.UBUNTU_2604_CLOUD_BASE, /\/resolute$/, "26.04 is resolute");
});

test("provision.sh lifts both userns restrictions: the sysctl, and 26.04's bwrap-userns-restrict profile (§4.1)", () => {
  const p = read("scripts/ci/guest/provision.sh");
  assert.match(p, /kernel\.apparmor_restrict_unprivileged_userns = 0/);
  // Without the second, a bwrap inside a bwrap fails on 26.04 whatever the
  // sysctl says (2026-09-30: four kernel-lane entries red on the first 26.04 run).
  assert.match(p, /ln -sf \/etc\/apparmor\.d\/bwrap-userns-restrict \/etc\/apparmor\.d\/disable\/bwrap-userns-restrict/);
  assert.match(p, /apparmor_parser -R \/etc\/apparmor\.d\/bwrap-userns-restrict/);
});

test("the guest runs Claude Code's own sandbox and a live drill run's sink (continuous-integration.md §9.9): socat and ripgrep installed and checked, unprivileged ports from 80 at build and at boot", () => {
  const p = read("scripts/ci/guest/provision.sh");
  const b = read("scripts/ci/guest/boot.sh");
  assert.match(p, /^\s+socat ripgrep\b/m, "in provision's apt list");
  assert.match(p, /for c in bwrap socat rg; do command -v "\$c"; done/, "the build fails without them");
  assert.match(p, /"net\.ipv4\.ip_unprivileged_port_start = 80"/);
  assert.match(b, /^sysctl -q -w net\.ipv4\.ip_unprivileged_port_start=80 /m);
  // the demo hosts go to the sink in the guest: nothing the nightly runs may
  // need the real api.github.com (agent-latest.sh took goose's release from it)
  assert.ok(!read("scripts/ci/agent-latest.sh").includes("api.github.com"), "agent-latest.sh uses GitHub's release redirect");
});

test("the guest has the interpreter families secret-readers-live's step (6g) pins (continuous-integration.md §4): mksh (lksh), yash and luajit installed and each checked to run", () => {
  const p = read("scripts/ci/guest/provision.sh");
  // Until 2026-10-17 no lane had one, so the step skipped everywhere.
  assert.match(p, /^\s+mksh yash luajit\s*$/m, "in provision's apt list");
  for (const run of [/mksh -c '/, /lksh -c '/, /yash -c '/, /luajit -e '/]) assert.match(p, run, "the build fails without it");
  // and the suite exercises each one present, not only the first
  const t = read("launcher/test/secret-readers-live.test.sh");
  assert.match(t, /for cand in ksh93 ksh mksh lksh yash posh fish luajit; do/);
  assert.match(t, /for i in "\$\{!RT_COPIES\[@\]\}"; do/);
});

test("the guest has Go for the sibling refusal's Go leg (continuous-integration.md §4): golang-go installed and checked to run", () => {
  const p = read("scripts/ci/guest/provision.sh");
  // rust.kernel allows one skip: a guest without go would skip the Go leg into red.
  assert.match(p, /^\s+golang-go \\$/m, "in provision's apt list");
  assert.match(p, /^\s+go version$/m, "the build fails without it");
});

test("the third-party baselines (continuous-integration.md §9.10): pinned by sha256, every PrivAiTe wheel and model file by hash, installed and checked by provision.sh", () => {
  const p = read("scripts/ci/guest/provision.sh");
  for (const k of ["FENCEPOST_SHA256", "GITLEAKS_SHA256"]) assert.match(pins[k], /^[0-9a-f]{64}$/, k);
  assert.match(pins.FENCEPOST_VERSION, /^\d+\.\d+\.\d+$/);
  assert.match(pins.GITLEAKS_VERSION, /^\d+\.\d+\.\d+$/);
  assert.match(pins.PRIVACY_FILTER_REVISION, /^[0-9a-f]{40}$/, "an immutable Hugging Face commit, not a branch");
  const req = read("scripts/ci/guest/privaite-requirements.txt").split("\n").filter((l) => l.trim() && !l.startsWith("#"));
  assert.ok(req.length > 50, "every dependency, not only PrivAiTe");
  for (const l of req) assert.match(l, /^[a-z0-9-]+(==[A-Za-z0-9.+!-]+| @ https:\/\/\S+\.whl) --hash=sha256:[0-9a-f]{64}$/, `pinned by version and hash: ${l}`);
  assert.ok(req.includes(req.find((l) => l.startsWith(`privaite==${pins.PRIVAITE_VERSION} `))), "the requirements pin pins.env's PrivAiTe");
  assert.ok(req.some((l) => l.startsWith("en-core-web-lg @ https://github.com/explosion/spacy-models/releases/download/")), "spaCy's model, by hash");
  const model = read("scripts/ci/guest/privaite-model.sha256").trim().split("\n");
  for (const l of model) assert.match(l, /^[0-9a-f]{64} {2}[A-Za-z0-9_./]+$/, l);
  assert.ok(model.some((l) => l.endsWith("onnx/model_q4.onnx_data")));
  assert.ok(p.includes('echo "$FENCEPOST_SHA256  $d/fencepost.zip" | sha256sum -c -'), "fencepost's zip checked");
  assert.match(p, /install_release_bin gitleaks \\\n.*gitleaks_\$\{GITLEAKS_VERSION\}_linux_x64\.tar\.gz" \\\n\s+"\$GITLEAKS_SHA256"/);
  assert.ok(p.includes("--require-hashes --no-deps --only-binary :all:"), "PrivAiTe from the hashed wheels only");
  assert.ok(p.includes('sha256sum -c --quiet "$SRC/scripts/ci/guest/privaite-model.sha256"'), "the model files checked");
  assert.ok(p.includes("resolve/$PRIVACY_FILTER_REVISION/$f"), "the model at the pinned revision");
});

test("the ggshield baseline (continuous-integration.md §9.10): its standalone release pinned by sha256, unpacked under /opt/mandu-baselines/ggshield, its version checked", () => {
  const p = read("scripts/ci/guest/provision.sh");
  assert.match(pins.GGSHIELD_VERSION, /^\d+\.\d+\.\d+$/);
  assert.match(pins.GGSHIELD_SHA256, /^[0-9a-f]{64}$/);
  assert.ok(p.includes('"https://github.com/GitGuardian/ggshield/releases/download/v$GGSHIELD_VERSION/ggshield-$GGSHIELD_VERSION-x86_64-unknown-linux-gnu.tar.gz"'), "the standalone Linux release");
  assert.ok(p.includes('echo "$GGSHIELD_SHA256  $d/ggshield.tar.gz" | sha256sum -c -'), "checked by sha256");
  assert.ok(p.includes('[[ "$("$BASELINES/ggshield/ggshield" --version)" == "ggshield, version $GGSHIELD_VERSION" ]]'), "it runs, at the pin");
});

test("the Docker Sandboxes baseline (continuous-integration.md §9.10): Docker's 24.04 package pinned by sha256, installed on the 24.04 guest only, its version checked; `ci` in the kvm group", () => {
  const p = read("scripts/ci/guest/provision.sh");
  assert.match(pins.SBX_VERSION, /^\d+\.\d+\.\d+$/);
  assert.match(pins.SBX_SHA256, /^[0-9a-f]{64}$/);
  assert.ok(p.includes('"https://github.com/docker/sbx-releases/releases/download/v$SBX_VERSION/DockerSandboxes-linux-amd64-ubuntu2404.deb"'), "Docker's 24.04 package");
  assert.ok(p.includes('echo "$SBX_SHA256  $d/docker-sbx.deb" | sha256sum -c -'), "checked by sha256");
  assert.ok(p.includes('[[ "$(sbx version | head -1)" == "sbx version v$SBX_VERSION "* ]]'), "it runs, at the pin");
  assert.ok(p.includes('getent group kvm >/dev/null && usermod -aG kvm "$CI_USER"'), "ci may open /dev/kvm");
});

test("the sandbox baselines (continuous-integration.md §9.10): OpenShell's three release tarballs and nono's by sha256, the images by digest, the pack's profile by sha256; provision.sh checks each and prepares the image cache", () => {
  const p = read("scripts/ci/guest/provision.sh");
  for (const k of ["OPENSHELL_CLI_SHA256", "OPENSHELL_GATEWAY_SHA256", "OPENSHELL_DRIVER_VM_SHA256", "NONO_SHA256", "NONO_CLAUDE_PACK_PROFILE_SHA256"]) assert.match(pins[k], /^[0-9a-f]{64}$/, k);
  for (const k of ["OPENSHELL_VERSION", "NONO_VERSION", "NONO_CLAUDE_PACK_VERSION"]) assert.match(pins[k], /^\d+\.\d+\.\d+$/, k);
  for (const k of ["OPENSHELL_SANDBOX_IMAGE_DIGEST", "OPENSHELL_BOOTSTRAP_IMAGE_DIGEST"]) assert.match(pins[k], /^sha256:[0-9a-f]{64}$/, `${k}: an image by digest, never a tag`);
  // both images public ones (Docker Official Images): the bootstrap image is
  // a public Ubuntu image in place of OpenShell's default NGC one
  for (const k of ["OPENSHELL_SANDBOX_IMAGE", "OPENSHELL_BOOTSTRAP_IMAGE"]) assert.match(pins[k], /^docker\.io\/library\/[a-z0-9-]+$/, `${k}: a Docker Official Image`);
  assert.equal(pins["OPENSHELL_BOOTSTRAP_IMAGE"], "docker.io/library/ubuntu", "the bootstrap image is Ubuntu, as OpenShell's default is");
  for (const [asset, sum] of [["openshell-x86_64-unknown-linux-musl.tar.gz", "OPENSHELL_CLI_SHA256"], ["openshell-gateway-x86_64-unknown-linux-gnu.tar.gz", "OPENSHELL_GATEWAY_SHA256"], ["openshell-driver-vm-x86_64-unknown-linux-gnu.tar.gz", "OPENSHELL_DRIVER_VM_SHA256"]]) {
    assert.ok(p.includes(`"${asset}:$${sum}"`), `provision.sh downloads ${asset} against $${sum}`);
  }
  assert.ok(p.includes('echo "${pair#*:}  $d/$asset" | sha256sum -c -'), "each OpenShell tarball checked");
  assert.ok(p.includes('[[ "$("$osb/$c" --version)" == "$c $OPENSHELL_VERSION" ]]'), "each OpenShell binary runs at its pin");
  assert.match(p, /install_release_bin nono \\\n[^\n]*nono-v\$NONO_VERSION-x86_64-unknown-linux-gnu\.tar\.gz" \\\n\s+"\$NONO_SHA256"/);
  assert.ok(p.includes('[[ "$(nono --version)" == "nono $NONO_VERSION" ]]'));
  assert.ok(p.includes('usermod -aG kvm "$CI_USER"'), "the MicroVM driver opens /dev/kvm");
  assert.ok(p.includes('"$OPENSHELL_SANDBOX_IMAGE@$OPENSHELL_SANDBOX_IMAGE_DIGEST" "$OPENSHELL_BOOTSTRAP_IMAGE@$OPENSHELL_BOOTSTRAP_IMAGE_DIGEST"'), "the image cache from the pinned digests");
  assert.ok(p.includes('as_ci nono pull "nolabs-ai/claude@$NONO_CLAUDE_PACK_VERSION"'));
  assert.ok(p.includes('echo "$NONO_CLAUDE_PACK_PROFILE_SHA256  /home/$CI_USER/.config/nono/packages/nolabs-ai/claude/profiles/claude.json" | sha256sum -c -'));
  assert.ok(p.includes("del(.enabledPlugins[\"nono@nolabs-ai\"])"), "the pack's plugin is not enabled for every other side's sessions");
  // the Codex pack (2026-10-19): pinned, its profile checked, and the user's
  // Codex config put back as it was
  assert.match(pins["NONO_CODEX_PACK_VERSION"], /^\d+\.\d+\.\d+$/);
  assert.match(pins["NONO_CODEX_PACK_PROFILE_SHA256"], /^[0-9a-f]{64}$/);
  assert.ok(p.includes('as_ci nono pull "nolabs-ai/codex@$NONO_CODEX_PACK_VERSION"'));
  assert.ok(p.includes('echo "$NONO_CODEX_PACK_PROFILE_SHA256  /home/$CI_USER/.config/nono/packages/nolabs-ai/codex/profiles/codex.json" | sha256sum -c -'));
  assert.ok(p.includes('if [[ $had_cxc == 1 ]]; then mv "$cxc.pre-nono" "$cxc"; else rm -f "$cxc"; fi'), "the pack's block is not left in every Codex session's config");
  assert.match(read("scripts/ci/guest/openshell-cache.sh"), /openshell sandbox create --name cache/);
});

test("provision.sh installs OpenCode 2 beside OpenCode 1: its own prefix, only `opencode2` on PATH, both versions checked", () => {
  const p = read("scripts/ci/guest/provision.sh");
  assert.match(pins.OPENCODE2_VERSION, /^2\.\d+\.\d+$/, "a released 2.x, not a 0.0.0-* prerelease");
  assert.ok(p.includes('--prefix /opt/opencode2 "@opencode/cli@$OPENCODE2_VERSION"'), "its own npm prefix");
  assert.ok(p.includes("ln -sf /opt/opencode2/bin/opencode2 /usr/local/bin/opencode2"), "only opencode2 linked");
  assert.ok(!/ln -sf \/opt\/opencode2\/bin\/opencode /.test(p), "never its `opencode`");
  assert.ok(p.includes('== "opencode v$OPENCODE2_VERSION" ]]') && p.includes('[[ "$(opencode --version)" == "$OPENCODE_VERSION" ]]'),
    "the image build fails when either command reports another version");
  assert.match(p, /for c in claude codex opencode opencode2 openclaw goose; do/, "it must RUN");
});

test("provision.sh points apt at the pinned mirror before it installs anything", () => {
  const p = read("scripts/ci/guest/provision.sh");
  const use = p.indexOf('use_apt_mirror "$UBUNTU_APT_MIRROR"');
  assert.ok(use > 0, "provision() calls use_apt_mirror with the pin");
  assert.ok(use < p.indexOf("apt_retry build-essential"), "the mirror is set before the first apt install");
  assert.ok(p.includes("s#https?://(archive|security)\\.ubuntu\\.com/ubuntu/?#$m/#g"),
    "both the archive and the security pocket are rewritten");
  assert.match(p, /no apt source took the mirror/, "an unmatched sources layout fails the build");
});

test("Dockerfile.ci's ARG defaults equal pins.env", () => {
  const df = read("packaging/docker/Dockerfile.ci");
  const args = {};
  for (const m of df.matchAll(/^ARG ([A-Z_]+)=(\S+)\s*$/gm)) args[m[1]] = m[2];
  for (const k of ["RUST_VERSION", "CLAUDE_CODE_VERSION", "CODEX_VERSION", "OPENCODE_VERSION", "OPENCLAW_VERSION"]) {
    assert.ok(k in args, `Dockerfile.ci has no ARG ${k}`);
    assert.equal(args[k], pins[k], `Dockerfile.ci ARG ${k}=${args[k]} but pins.env says ${pins[k]} (bump both)`);
  }
  // Every ARG of Dockerfile.ci that pins.env also names agrees (future pins).
  for (const [k, v] of Object.entries(args)) if (k in pins) assert.equal(v, pins[k], k);
  // Its base image is the pinned node major.
  const from = /^FROM node:(\d+)/m.exec(df);
  assert.ok(from, "Dockerfile.ci FROM node:<major>");
  assert.equal(from[1], pins.NODE_VERSION.split(".")[0]);
});

// The release-binary agents: every <AGENT>_VERSION + <AGENT>_SHA256 pair in
// pins.env other than bubblewrap (built from source, not an agent) and
// cargo-audit (a CI tool, its own test below), and the third-party baselines
// (fencepost, gitleaks: not agents, their own test above).
const NOT_AGENTS = new Set(["BWRAP_SHA256", "CARGO_AUDIT_SHA256", "FENCEPOST_SHA256", "GITLEAKS_SHA256"]);
// ggshield, a baseline too (its own test below)
NOT_AGENTS.add("GGSHIELD_SHA256");
// Docker Sandboxes, a baseline too (its own test below)
NOT_AGENTS.add("SBX_SHA256");
// nono, a baseline too (the sandbox baselines' test above)
NOT_AGENTS.add("NONO_SHA256");
const releaseBins = Object.keys(pins)
  .filter((k) => k.endsWith("_SHA256") && !NOT_AGENTS.has(k) && `${k.slice(0, -7)}_VERSION` in pins)
  .map((k) => k.slice(0, -7));

test("cargo-audit (the dependency audit, continuous-integration.md §14.2): pinned by sha256, installed by provision.sh and the GitHub audit job from the same pins", () => {
  assert.match(pins.CARGO_AUDIT_VERSION, /^\d+\.\d+\.\d+$/);
  assert.match(pins.CARGO_AUDIT_SHA256, /^[0-9a-f]{64}$/);
  const p = read("scripts/ci/guest/provision.sh");
  assert.ok(/install_release_bin cargo-audit \\\n[^\n]*cargo-audit-x86_64-unknown-linux-musl-v\$CARGO_AUDIT_VERSION\.tgz[^\n]*\n\s*"\$CARGO_AUDIT_SHA256"/.test(p),
    "provision.sh installs the musl release with $CARGO_AUDIT_VERSION and $CARGO_AUDIT_SHA256");
  assert.ok(p.includes('[[ "$(cargo-audit --version)" == "cargo-audit $CARGO_AUDIT_VERSION" ]]'), "provision.sh checks it runs, at its pin");
  const yml = read(".github/workflows/ci.yml");
  assert.match(yml, /CARGO_AUDIT_VERSION.*scripts\/ci\/pins\.env|scripts\/ci\/pins\.env[\s\S]{0,400}CARGO_AUDIT_SHA256/, "ci.yml reads the pins, keeps no copy");
  assert.ok(yml.includes("sha256sum -c -"), "ci.yml checks the download");
  assert.doesNotMatch(yml, new RegExp(pins.CARGO_AUDIT_SHA256), "no second copy of the sum to drift");
});

test("clippy is installed wherever rust.clippy runs: the CI image, the docker rig, the GitHub rust job", () => {
  assert.match(read("scripts/ci/guest/provision.sh"), /--default-toolchain '\$RUST_VERSION' [^\n]*--component clippy/);
  assert.match(read("packaging/docker/Dockerfile.ci"), /--component clippy/);
  assert.match(read(".github/workflows/ci.yml"), /rustup toolchain install "\$RUSTUP_TOOLCHAIN" [^\n]*--component clippy/);
});

test("release-binary agents: each pinned pair is installed by provision.sh and Dockerfile.ci, sha-checked, and run", () => {
  assert.ok(releaseBins.includes("GOOSE"), "Goose is pinned as a release binary");
  const p = read("scripts/ci/guest/provision.sh");
  const df = read("packaging/docker/Dockerfile.ci");
  const loop = /for c in ([a-z0-9 ]+); do command -v "\$c"; "\$c" --version; done/.exec(p);
  assert.ok(loop, "provision.sh runs every agent CLI's --version");
  for (const a of releaseBins) {
    const cmd = a.toLowerCase();
    assert.match(pins[`${a}_SHA256`], /^[0-9a-f]{64}$/, `${a}_SHA256 is a sha256`);
    assert.match(pins[`${a}_VERSION`], /^\d+\.\d+\.\d+$/, `${a}_VERSION is a release version`);
    assert.ok(new RegExp(`install_release_bin ${cmd} \\\\\\n[^\\n]*\\$${a}_VERSION[^\\n]*\\n\\s*"\\$${a}_SHA256"`).test(p),
      `provision.sh installs ${cmd} with $${a}_VERSION and $${a}_SHA256`);
    assert.ok(loop[1].split(/\s+/).includes(cmd), `provision.sh checks ${cmd} --version`);
    assert.ok(df.includes(`ARG ${a}_VERSION=${pins[`${a}_VERSION`]}`), `Dockerfile.ci ARG ${a}_VERSION`);
    assert.ok(df.includes(`ARG ${a}_SHA256=${pins[`${a}_SHA256`]}`), `Dockerfile.ci ARG ${a}_SHA256`);
    assert.ok(df.includes(`echo "\${${a}_SHA256}  `) && df.includes("sha256sum -c -"), `Dockerfile.ci checks ${cmd}'s sha256`);
    assert.ok(df.includes(`&& ${cmd} --version`), `Dockerfile.ci runs ${cmd} --version`);
  }
  assert.match(p, /install_release_bin\(\) \{[\s\S]*?sha256sum -c -[\s\S]*?\n\}/, "install_release_bin checks the sha256");
});

test(".github/workflows/ci.yml tests at pins.env's node and rust", () => {
  const yml = read(".github/workflows/ci.yml");
  const node = /NODE_VERSION:\s*"?([0-9.]+)"?/.exec(yml);
  assert.ok(node, "ci.yml sets NODE_VERSION");
  assert.equal(node[1], pins.NODE_VERSION);
  const rust = /RUSTUP_TOOLCHAIN:\s*"?([0-9.]+)"?/.exec(yml);
  assert.ok(rust, "ci.yml sets RUSTUP_TOOLCHAIN");
  assert.equal(rust[1], pins.RUST_VERSION);
});

test("the workspace's rust-version is the pinned rust's major.minor", () => {
  const cargo = read("interceptors/Cargo.toml");
  const rv = /rust-version\s*=\s*"([0-9.]+)"/.exec(cargo);
  assert.ok(rv, "interceptors/Cargo.toml declares rust-version");
  assert.equal(pins.RUST_VERSION.split(".").slice(0, 2).join("."), rv[1].split(".").slice(0, 2).join("."));
});

// The guest's PATH agent CLIs are what every per-push replay drill runs, so
// they track the tested ranges (launcher/src/agent-versions.ts) rather than
// sit at a floor: 2.1.273 / 0.144.1 lagged the ranges' tops and the agent
// SDKs' bundled CLIs for weeks (continuous-integration.md §4).
const semver = (v) => v.split(".").map(Number);
const cmp = (a, b) => { const [x, y] = [semver(a), semver(b)]; for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i]; return 0; };

test("the claude and codex pins lie inside their tested ranges, and are not older than the agent SDK fixture's codex", () => {
  const av = read("launcher/src/agent-versions.ts");
  for (const [agent, key] of [["claude", "CLAUDE_CODE_VERSION"], ["codex", "CODEX_VERSION"]]) {
    const m = new RegExp(`\\n  ${agent}: \\{\\s*name: "[^"]+",\\s*min: "([0-9.]+)",\\s*max: "([0-9.]+)"`).exec(av);
    assert.ok(m, `agent-versions.ts has a ${agent} range`);
    assert.match(pins[key], /^\d+\.\d+\.\d+$/, `${key} is a release version`);
    assert.ok(cmp(pins[key], m[1]) >= 0 && cmp(pins[key], m[2]) <= 0,
      `${key}=${pins[key]} is outside the tested ${agent} range ${m[1]} to ${m[2]}`);
  }
  // @openai/codex-sdk installs the codex CLI it drives; the PATH codex the
  // other suites run is not older than it.
  const lock = JSON.parse(read("tests/fixtures/agent-sdk-host/package-lock.json"));
  const sdkCodex = lock.packages["node_modules/@openai/codex"]?.version;
  assert.ok(sdkCodex, "the agent-sdk-host lockfile resolves @openai/codex");
  assert.ok(cmp(pins.CODEX_VERSION, sdkCodex) >= 0, `CODEX_VERSION=${pins.CODEX_VERSION} is older than the SDK's codex ${sdkCodex}`);
});
