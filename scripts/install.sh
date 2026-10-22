#!/bin/sh
# Mandu installer (docs/design/distribution/packaging.md §3, comparisons.md §3.1).
#
#   curl -fsSL <host>/install.sh | sh
#   curl -fsSL <host>/install.sh | sh -s -- --package ./mandusec-mandu-0.2.0-beta.8.tgz
#   sh install.sh --package https://<host>/mandusec-mandu-<v>.tgz --sha256 <hex>
#
# A release's own copy of this script names that release's tarball and its
# SHA-256 as the default package (PACKAGE_DEFAULT below, rewritten when the
# release is published), so `curl <release>/install.sh | sh` installs exactly
# the published file or nothing. Run in a folder that already holds that
# tarball (downloaded from the release page), it installs the local file,
# checked against the same SHA-256.
#
# Installs the SAME npm artifact as `npm install -g @mandusec/mandu`, for the
# current user, with no sudo:
#   1. a Node that meets Mandu's floor (NODE_FLOOR, launcher/src/node-floor.ts):
#      the one on PATH when it is new enough, else a pinned Node downloaded
#      from nodejs.org into the prefix, its SHA-256 checked against the
#      release's SHASUMS256.txt;
#   2. the package, into its own npm prefix (never the system's);
#   3. `mandu` in the bin dir: a small wrapper that runs the package with
#      THAT Node, whatever `node` is first on PATH later, and falls back to
#      the node on PATH if that Node disappears (an nvm uninstall) instead of
#      failing with "not found".
#
# Settings (flag, or environment):
#   --package SPEC      MANDU_PACKAGE       npm spec, tarball path or URL (default @mandusec/mandu)
#   --sha256 HEX        MANDU_PACKAGE_SHA256  the tarball's SHA-256: checked (a URL is
#                                             downloaded first) before npm sees it
#   --prefix DIR        MANDU_PREFIX        default ~/.local/share/mandu
#   --bin-dir DIR       MANDU_BIN_DIR       default ~/.local/bin
#   --node-version V    MANDU_NODE_VERSION  the Node to download when needed (default below)
#                       MANDU_NODE_MIRROR   default https://nodejs.org/dist (a file:// mirror works)
#   --dry-run                                 print the plan, change nothing
set -eu

NODE_FLOOR="22.13.0"
NODE_PIN="22.22.1"

# The default package and, for a tarball, its SHA-256 (empty for the npm spec).
PACKAGE_DEFAULT="@mandusec/mandu"
PACKAGE_DEFAULT_SHA256=""
PACKAGE="${MANDU_PACKAGE:-$PACKAGE_DEFAULT}"
PACKAGE_SHA256="${MANDU_PACKAGE_SHA256:-}"
PREFIX="${MANDU_PREFIX:-${HOME}/.local/share/mandu}"
BIN_DIR="${MANDU_BIN_DIR:-${HOME}/.local/bin}"
NODE_VERSION="${MANDU_NODE_VERSION:-$NODE_PIN}"
NODE_MIRROR="${MANDU_NODE_MIRROR:-https://nodejs.org/dist}"
DRY_RUN=0

say() { printf 'mandu-install: %s\n' "$*"; }
die() { printf 'mandu-install: error: %s\n' "$*" >&2; exit 1; }
run() { if [ "$DRY_RUN" = 1 ]; then say "would run: $*"; else "$@"; fi; }

usage() {
  # The header comment block, however long it grows.
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0" 2>/dev/null
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --package) PACKAGE="${2:?--package needs a value}"; shift 2 ;;
    --sha256) PACKAGE_SHA256="${2:?--sha256 needs a value}"; shift 2 ;;
    --prefix) PREFIX="${2:?--prefix needs a value}"; shift 2 ;;
    --bin-dir) BIN_DIR="${2:?--bin-dir needs a value}"; shift 2 ;;
    --node-version) NODE_VERSION="${2:?--node-version needs a value}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done
# The default package's hash applies only to the default package. A release
# copy run next to its own tarball (the release's files downloaded by hand,
# as a private repository requires) installs that file instead of fetching
# the URL: the hash check is the same either way.
if [ "$PACKAGE" = "$PACKAGE_DEFAULT" ] && [ -z "$PACKAGE_SHA256" ]; then
  PACKAGE_SHA256="$PACKAGE_DEFAULT_SHA256"
  case "$PACKAGE" in
    http://*|https://*) [ -z "$PACKAGE_SHA256" ] || [ ! -f "./${PACKAGE##*/}" ] || PACKAGE="./${PACKAGE##*/}" ;;
  esac
fi
PACKAGE_SHA256="$(printf '%s' "$PACKAGE_SHA256" | awk '{ print tolower($0) }')"
case "$PACKAGE_SHA256" in
  "") ;;
  *[!0-9a-f]*) die "--sha256 takes 64 hex digits, not $PACKAGE_SHA256" ;;
  *) [ "${#PACKAGE_SHA256}" = 64 ] || die "--sha256 takes 64 hex digits, not $PACKAGE_SHA256" ;;
esac

tmp=""
ptmp=""
cleanup() { [ -z "$tmp" ] || rm -rf "$tmp"; [ -z "$ptmp" ] || rm -rf "$ptmp"; }
trap cleanup EXIT

# a >= b for dotted x.y.z versions (a leading v is ignored)
ver_ge() {
  awk -v a="${1#v}" -v b="${2#v}" 'BEGIN {
    split(a, x, "."); split(b, y, ".")
    for (i = 1; i <= 3; i++) { if (x[i] + 0 > y[i] + 0) exit 0; if (x[i] + 0 < y[i] + 0) exit 1 }
    exit 0 }'
}

# ── preflight ────────────────────────────────────────────────────────────────
[ "$(id -u)" != 0 ] || die "run this as your own user, not root: Mandu installs and runs per user (no sudo needed)"

case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *) die "unsupported OS $(uname -s): Mandu runs on Linux and macOS (on Windows, use WSL2)" ;;
esac
# WSL1 translates syscalls instead of running a Linux kernel: no Landlock, no
# seccomp user notification, no user namespaces, so none of Mandu's kernel
# protections can run (mandu doctor says the same; launcher/src/wsl.ts).
# WSL2 kernels carry "microsoft-standard", WSL1 reports "...-Microsoft".
if [ "$OS" = linux ]; then
  case "$(uname -r)" in
    *[Mm]icrosoft-standard*|*[Ww][Ss][Ll]2*) ;;
    *[Mm]icrosoft*) die "this is WSL1, which cannot run Mandu's protections (no Landlock, no seccomp user notification, no user namespaces): convert the distribution to WSL2 from Windows (wsl --set-version <distro> 2), then re-run" ;;
  esac
fi
# ARCH names both the Node download and the package's prebuilt native bins
# (dist/native/<os>-<arch>/, one tarball for every CPU: packaging.md §11.3).
case "$(uname -m)" in
  x86_64|amd64) ARCH=x64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported CPU $(uname -m): Mandu supports 64-bit x86 (x86_64) and 64-bit ARM (aarch64)" ;;
esac
ver_ge "$NODE_VERSION" "$NODE_FLOOR" || die "--node-version $NODE_VERSION is below Mandu's floor $NODE_FLOOR"

fetch() { # url dest
  if command -v curl >/dev/null 2>&1; then run curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then run wget -q "$1" -O "$2"
  else die "need curl or wget to download $1"; fi
}
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "need sha256sum or shasum to verify the Node download"; fi
}

# ── 1. Node ──────────────────────────────────────────────────────────────────
NODE=""
if command -v node >/dev/null 2>&1; then
  have="$(node --version 2>/dev/null || true)"
  if [ -n "$have" ] && ver_ge "$have" "$NODE_FLOOR"; then
    NODE="$(command -v node)"
    say "using Node $have at $NODE (floor $NODE_FLOOR)"
  else
    say "Node on PATH is ${have:-unreadable}, below Mandu's floor $NODE_FLOOR: installing Node $NODE_VERSION for Mandu only"
  fi
else
  say "no Node on PATH: installing Node $NODE_VERSION for Mandu only"
fi

if [ -z "$NODE" ]; then
  name="node-v${NODE_VERSION}-${OS}-${ARCH}"
  base="${NODE_MIRROR}/v${NODE_VERSION}"
  tmp="$(mktemp -d)"
  fetch "$base/${name}.tar.gz" "$tmp/${name}.tar.gz"
  fetch "$base/SHASUMS256.txt" "$tmp/SHASUMS256.txt"
  if [ "$DRY_RUN" = 0 ]; then
    want="$(awk -v f="${name}.tar.gz" '$2 == f {print $1}' "$tmp/SHASUMS256.txt")"
    [ -n "$want" ] || die "${name}.tar.gz is not listed in $base/SHASUMS256.txt"
    got="$(sha256_of "$tmp/${name}.tar.gz")"
    [ "$want" = "$got" ] || die "checksum mismatch for ${name}.tar.gz (expected $want, got $got): not installing"
    say "verified ${name}.tar.gz (sha256 $got)"
  fi
  run mkdir -p "$PREFIX"
  run rm -rf "$PREFIX/node"
  run mkdir -p "$PREFIX/node"
  run tar -xzf "$tmp/${name}.tar.gz" -C "$PREFIX/node" --strip-components=1
  NODE="$PREFIX/node/bin/node"
fi

# ── 2. the package, in its own prefix ────────────────────────────────────────
NPM="$(dirname "$NODE")/npm"
[ -x "$NPM" ] || [ "$DRY_RUN" = 1 ] || die "no npm next to $NODE"
# With a SHA-256 the package is a tarball that npm only sees once it matches:
# a URL is downloaded here first, and a mismatch installs nothing.
SPEC="$PACKAGE"
if [ -n "$PACKAGE_SHA256" ]; then
  case "$PACKAGE" in
    http://*|https://*|file://*)
      ptmp="$(mktemp -d)"
      SPEC="$ptmp/mandu-package.tgz"
      fetch "$PACKAGE" "$SPEC" ;;
    *) [ -f "$PACKAGE" ] || [ "$DRY_RUN" = 1 ] || die "--sha256 needs a tarball path or URL; $PACKAGE is neither" ;;
  esac
  if [ "$DRY_RUN" = 0 ]; then
    got="$(sha256_of "$SPEC")"
    [ "$got" = "$PACKAGE_SHA256" ] || die "checksum mismatch for $PACKAGE (expected $PACKAGE_SHA256, got $got): not installing"
    say "verified $PACKAGE (sha256 $got)"
  fi
fi
say "installing $PACKAGE into $PREFIX/pkg"
run mkdir -p "$PREFIX/pkg"
run env PATH="$(dirname "$NODE"):$PATH" "$NPM" install -g --prefix "$PREFIX/pkg" --no-audit --no-fund "$SPEC"

ENTRY="$PREFIX/pkg/lib/node_modules/@mandusec/mandu/bin/mandu.mjs"
[ -f "$ENTRY" ] || [ "$DRY_RUN" = 1 ] || die "the package did not install $ENTRY"

# Remember the release-installer channel for update notices. This marker is
# local installation state, never part of the published npm tarball.
run touch "$PREFIX/pkg/lib/node_modules/@mandusec/mandu/.mandu-installer"

# ── 3. the command ───────────────────────────────────────────────────────────
run mkdir -p "$BIN_DIR"
if [ "$DRY_RUN" = 1 ]; then
  say "would write $BIN_DIR/mandu: exec \"$NODE\" (or the node on PATH if it is gone) \"$ENTRY\" \"\$@\""
else
  cat > "$BIN_DIR/mandu" <<WRAPPER
#!/bin/sh
# written by the Mandu installer: run Mandu with the Node it was installed
# for, and if that Node is gone (an nvm uninstall, a removed toolchain), with
# the node on PATH. bin/mandu.mjs checks the version floor either way.
NODE="$NODE"
[ -x "\$NODE" ] || NODE="\$(command -v node 2>/dev/null || true)"
if [ -z "\$NODE" ]; then
  echo "mandu: no Node to run on: $NODE is gone and there is no node on PATH." >&2
  echo "mandu: install Node $NODE_FLOOR or newer, or re-run the Mandu installer (it can install a Node for Mandu only)." >&2
  exit 127
fi
exec "\$NODE" "$ENTRY" "\$@"
WRAPPER
  chmod 755 "$BIN_DIR/mandu"
  version="$("$BIN_DIR/mandu" --version 2>/dev/null)" || die "installed, but $BIN_DIR/mandu --version failed"
  say "installed $version at $BIN_DIR/mandu"
fi

# The package carries its confinement helpers prebuilt per CPU; the launcher
# picks this machine's at run time. Say whether this CPU is among them.
if [ "$DRY_RUN" = 0 ] && [ "$OS" = linux ]; then
  if [ -d "$(dirname "$(dirname "$ENTRY")")/dist/native/$OS-$ARCH" ]; then
    say "prebuilt confinement helpers for $OS-$ARCH: included"
  else
    say "note: this package has no prebuilt confinement helpers for $OS-$ARCH; Mandu runs, and mandu doctor shows what that leaves out"
  fi
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say "add $BIN_DIR to your PATH, e.g.: echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.profile" ;;
esac
say "next: mandu doctor, then mandu claude"
