#!/usr/bin/env bash
#
# matrix-provision.test.sh — unit tests for the qemu guest's PROVISIONING GATE
# (scripts/matrix/lib/qemu.sh, qemu_userdata). cloud-init's package module only
# warns when the Ubuntu mirror is unreachable; before the gate, a suite then ran
# on a half-provisioned guest and failed as "linker `cc` not found, 0 passed /
# 0 failed" (ubuntu-2604 kernel suite, 2026-09-25). The gate re-checks every
# declared package, retries apt, and fails as a named provisioning error.
#
# Renders the real user-data, cuts the gate out of the rendered guest script and
# runs it against stub apt-get / sleep / probe commands. No VM, no network.
#
# Also the two executor additions of os-test-matrix.md §10.5: the cached
# PROVISIONED LAYER (its cache key, the provisioning boot's shares, reuse,
# expiry, the fall-back when it cannot be built) and the MANUAL LANE
# (`run.sh --interactive`: loopback-only ssh forward, a per-run key, the
# live-credential refusal), both driven through the real executor against a
# stub qemu.
#
# Run:  bash scripts/test/matrix-provision.test.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MATRIX="$HERE/../matrix"
PASS=0; FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
# The guest registry (`mandu reap`) of the stub boots below: never the host's.
export MANDU_RUNTIME_DIR="$WORK/rt"

render() {  # render <deps> <dir> : writes <dir>/user-data + <dir>/guest-runner.sh
  mkdir -p "$2"
  ( source "$MATRIX/lib/common.sh"; source "$MATRIX/lib/qemu.sh"
    RUN_WORK="$2" TARGET_NAME=t LABELS=l SYSCTLS=""
    qemu_userdata s "$1" "$2/user-data" ) >/dev/null 2>&1
}

# ── 1. cloud-init packages and the gate's list are ONE list ────────────────────
for deps in "none" "cargo" "node" "cargo node"; do
  d="$WORK/r-${deps// /-}"; render "$deps" "$d"
  yaml="$(sed -n '/^packages:/,/^write_files:/p' "$d/user-data" | sed -n 's/^  - //p' | tr '\n' ' ' | sed 's/ $//')"
  gate="$(sed -n 's/^  for pkg in \(.*\); do$/\1/p' "$d/guest-runner.sh")"
  [[ -n "$yaml" && "$yaml" == "$gate" ]] && pass "deps='$deps': gate list == cloud-init packages ($gate)" \
    || fail "deps='$deps': cloud-init [$yaml] != gate [$gate]"
  grep -q '@PKGS@' "$d/guest-runner.sh" && fail "deps='$deps': @PKGS@ left unsubstituted" || pass "deps='$deps': no unsubstituted token"
  bash -n "$d/guest-runner.sh" && pass "deps='$deps': rendered guest script parses" || fail "deps='$deps': guest script syntax"
done
d="$WORK/r-cargo"
out="$(env -u HOME -u USER bash -c "$(grep -m1 '^export HOME=' "$d/guest-runner.sh"); echo \"\$HOME \$USER\"")"
[[ "$out" == "/root root" ]] && pass "guest runner sets HOME/USER when cloud-init gives none" || fail "HOME/USER not set: '$out'"
g_line="$(grep -n 'provisioning: all declared packages present' "$d/guest-runner.sh" | cut -d: -f1)"
r_line="$(grep -n '=== running suite' "$d/guest-runner.sh" | cut -d: -f1)"
c_line="$(grep -n 'rustup.rs' "$d/guest-runner.sh" | cut -d: -f1)"
[[ -n "$g_line" && "$g_line" -lt "$c_line" && "$g_line" -lt "$r_line" ]] \
  && pass "gate runs before toolchain install and before the suite" || fail "gate order: gate=$g_line rustup=$c_line suite=$r_line"

# ── 2. the gate's behavior, on stubs ───────────────────────────────────────────
render "node" "$WORK/n"   # curl rsync git python3 make g++ (no absolute-path probes)
{ echo 'finish() { echo "FINISH $1"; exit 0; }'
  sed -n '/^# Provisioning gate/,/provisioning: all declared packages present/p' "$WORK/n/guest-runner.sh"
} > "$WORK/gate.sh"

scenario() {  # scenario <name> <present probes> <apt mode: ok|fail> ; sets OUT, APT_CALLS
  local bin="$WORK/bin-$1"; mkdir -p "$bin"; : > "$WORK/apt-$1.log"
  local c; for c in $2; do printf '#!/bin/sh\n' > "$bin/$c"; chmod +x "$bin/$c"; done
  printf '#!/bin/sh\n: > /dev/null\n' > "$bin/sleep"; chmod +x "$bin/sleep"
  cat > "$bin/apt-get" <<STUB
#!/bin/bash
echo "\$*" >> "$WORK/apt-$1.log"
case " \$* " in *" install "*)
  [ "$3" = ok ] || exit 100
  for a in "\$@"; do case "\$a" in -*|install|Acquire*|DPkg*) ;; *) printf '#!/bin/sh\n' > "$bin/\$a"; chmod +x "$bin/\$a" ;; esac; done ;;
esac
exit 0
STUB
  chmod +x "$bin/apt-get"
  OUT="$(PATH="$bin" /bin/bash "$WORK/gate.sh" 2>&1)"
  APT_CALLS="$(grep -c ' install ' "$WORK/apt-$1.log" || true)"
}

scenario complete "curl rsync git python3 make g++" ok
[[ "$OUT" == *"all declared packages present"* && "$OUT" != *FINISH* && "$APT_CALLS" == 0 ]] \
  && pass "fully provisioned guest: no apt call, gate passes" || fail "complete: calls=$APT_CALLS out=$OUT"

scenario recovers "curl rsync git python3 make" ok
[[ "$OUT" == *"left these uninstalled: g++"* && "$OUT" == *"all declared packages present"* && "$OUT" != *FINISH* && "$APT_CALLS" == 1 ]] \
  && pass "missing g++: one apt retry installs it, gate passes" || fail "recovers: calls=$APT_CALLS out=$OUT"
grep -q 'install -y -q g++$' "$WORK/apt-recovers.log" && pass "retry installs ONLY the missing package" || fail "retry args: $(cat "$WORK/apt-recovers.log")"
grep -q 'Acquire::Retries=5' "$WORK/apt-recovers.log" && pass "apt runs with Acquire::Retries" || fail "no Acquire::Retries on apt"

scenario unreachable "curl rsync git python3" fail
[[ "$OUT" == *"FINISH fail: provisioning: packages missing after retries: make g++"* && "$OUT" != *"all declared packages present"* && "$APT_CALLS" == 4 ]] \
  && pass "mirror down: 4 attempts, then a NAMED provisioning failure (suite never runs)" || fail "unreachable: calls=$APT_CALLS out=$OUT"

# ── 3. the provisioned snapshot layer (os-test-matrix.md §10.5 item 2) ────
lib() { ( source "$MATRIX/lib/common.sh"; source "$MATRIX/lib/qemu.sh"; "$@" ); }
k1="$(lib qemu_layer_key d1 "curl rsync git")"
k1b="$(lib qemu_layer_key d1 "curl rsync git")"
k2="$(lib qemu_layer_key d2 "curl rsync git")"
k3="$(lib qemu_layer_key d1 "curl rsync git python3 make g++")"
kv="$( source "$MATRIX/lib/common.sh"; source "$MATRIX/lib/qemu.sh"; QEMU_LAYER_VERSION=999; qemu_layer_key d1 "curl rsync git" )"
[[ "$k1" =~ ^[0-9a-f]{16}$ && "$k1" == "$k1b" ]] && pass "cache key: 16 hex chars, stable for the same image and packages" || fail "key: '$k1' '$k1b'"
[[ "$k1" != "$k2" ]] && pass "cache key changes with the image digest" || fail "key ignores the image"
[[ "$k1" != "$k3" ]] && pass "cache key changes with the package list" || fail "key ignores the packages"
[[ "$k1" != "$kv" ]] && pass "cache key changes with QEMU_LAYER_VERSION" || fail "key ignores the layer version"
[[ "$(lib qemu_pkg_list "")" == "curl rsync git" ]] && pass "no deps: the layer holds curl rsync git" || fail "pkg list: $(lib qemu_pkg_list "")"
render "cargo node" "$WORK/pl"
[[ "$(sed -n 's/^  for pkg in \(.*\); do$/\1/p' "$WORK/pl/guest-runner.sh")" == "$(lib qemu_pkg_list "cargo node")" ]] \
  && pass "the gate's list is qemu_pkg_list's (the key covers what the guest installs)" || fail "gate list != qemu_pkg_list"

render_suite() {  # render_suite <suite> <dir> [pubkey]
  mkdir -p "$2"
  ( source "$MATRIX/lib/common.sh"; source "$MATRIX/lib/qemu.sh"
    RUN_WORK="$2" TARGET_NAME=t LABELS=l SYSCTLS=""
    qemu_userdata "$1" "" "$2/user-data" "${3:-}" ) >/dev/null 2>&1
}
render_suite __provision__ "$WORK/pv"
G="$WORK/pv/guest-runner.sh"
b_line="$(grep -n '^if \[\[ "\$SUITE" == __provision__ \]\]; then' "$G" | cut -d: -f1)"
g_line="$(grep -n 'provisioning: all declared packages present' "$G" | cut -d: -f1)"
rs_line="$(grep -n 'rsync -a' "$G" | head -1 | cut -d: -f1)"
[[ -n "$b_line" && "$g_line" -lt "$b_line" && "$b_line" -lt "$rs_line" ]] \
  && pass "the provisioning boot stops after the package gate, before the repo copy" || fail "provision branch order: gate=$g_line branch=$b_line rsync=$rs_line"
branch="$(sed -n "${b_line},/^fi\$/p" "$G")"
[[ "$branch" == *'finish "provisioned"'* && "$branch" == *'truncate -s 0 /etc/machine-id'* ]] \
  && pass "it reports RESULT=provisioned and leaves no shared machine-id" || fail "provision branch: $branch"

# The executor on stubs: a provisioning boot (out share only) writes
# $QSTUB_PROVISION into RESULT; a run boot writes pass; an interactive boot
# (hostfwd) writes interactive. Every call's argv is kept.
SB="$WORK/snapstub"; mkdir -p "$SB"
cat > "$SB/qemu-system-x86_64" <<'Q'
#!/bin/bash
[[ "$1" == -device && "$2" == help ]] && { echo 'name "virtio-9p-pci"'; exit 0; }
[[ "$1" == --version ]] && { echo "QEMU emulator version 0 (stub)"; exit 0; }
n=$(( $(cat "$QSTUB_DIR/count" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$QSTUB_DIR/count"
printf '%s\n' "$@" > "$QSTUB_DIR/argv.$n"
out="" pf=""; while [[ $# -gt 0 ]]; do
  [[ "$1" == -fsdev && "$2" == *id=fsout,* ]] && out="$(sed 's/.*path=\([^,]*\).*/\1/' <<<"$2")"
  [[ "$1" == -pidfile ]] && pf="$2"; shift
done
# As qemu's -pidfile does; then note whether the harness registered this
# guest for `mandu reap` while it ran (scripts/lib/guest-registry.sh).
if [[ -n "$pf" ]]; then
  echo $$ > "$pf"
  for _ in $(seq 50); do
    compgen -G "$MANDU_RUNTIME_DIR/vm-guests/*-$$.json" >/dev/null && { echo "$(basename "$(compgen -G "$MANDU_RUNTIME_DIR/vm-guests/*-$$.json")")" > "$QSTUB_DIR/registered.$n"; break; }
    sleep 0.1
  done
fi
if grep -q 'hostfwd=' "$QSTUB_DIR/argv.$n"; then echo interactive > "$out/RESULT"
elif grep -q 'mount_tag=reposrc' "$QSTUB_DIR/argv.$n"; then echo pass > "$out/RESULT"
else echo "$QSTUB_PROVISION" > "$out/RESULT"; fi
exit 0
Q
cat > "$SB/qemu-img" <<'Q'
#!/bin/bash
echo "$*" >> "$QSTUB_DIR/img.log"
[[ "$1" == create ]] && echo qcow2 > "${@: -2:1}"
exit 0
Q
printf '#!/bin/bash\nwhile [[ $# -gt 0 ]]; do [[ "$1" == -output ]] && touch "$2"; shift; done\n' > "$SB/genisoimage"
chmod +x "$SB"/*

snap_run() {  # snap_run <name> <cache dir> <provision result> [VAR=value...]; sets RC, BOOTS, LOGTXT, Q
  local name="$1" cache="$2" prov="$3"; shift 3
  local d="$WORK/snap-$name"; mkdir -p "$d/matrix/suites" "$d/run" "$d/q" "$cache"
  printf '#!/bin/bash\n# deps:\n' > "$d/matrix/suites/s.sh"
  [[ -f "$cache/base.img" ]] || echo img > "$cache/base.img"
  Q="$d/q"
  LOGTXT="$(
    env "$@" PATH="$SB:$PATH" QSTUB_PROVISION="$prov" QSTUB_DIR="$Q" MANDU_VM_CACHE="$cache" bash -c '
      source "'"$MATRIX"'/lib/common.sh"; source "'"$MATRIX"'/lib/qemu.sh"
      MATRIX_DIR="'"$d"'/matrix" REPO_ROOT="'"$d"'" TARGET_NAME=t RUN_WORK="'"$d"'/run"
      IMAGE_URL=http://x/base.img IMAGE_SHA256="" CPUS=1 MEM=64 TIMEOUT=60 LABELS=l SYSCTLS=""
      executor_run s' 2>&1
  )"; RC=$?
  BOOTS="$(cat "$Q/count" 2>/dev/null || echo 0)"
}
C1="$WORK/cache1"
snap_run first "$C1" provisioned
layer="$(ls "$C1"/provisioned-t-*.qcow2 2>/dev/null | head -1)"
[[ $RC -eq 0 && $BOOTS -eq 2 && -n "$layer" ]] && pass "empty cache: one provisioning boot builds the layer, then the run boots (PASS)" \
  || fail "first: rc=$RC boots=$BOOTS layer=$layer; $(tail -5 <<<"$LOGTXT")"
grep -q "mount_tag=out" "$Q/argv.1" && ! grep -Eq "mount_tag=(reposrc|artifacts)" "$Q/argv.1" \
  && pass "the provisioning boot gets its out share only: no repo, no artifacts (no credential can reach the layer)" || fail "provision argv: $(tr '\n' ' ' < "$Q/argv.1")"
grep -q -- "-b $layer " "$Q/img.log" && pass "the run's overlay is backed by the provisioned layer" || fail "overlay backing: $(cat "$Q/img.log")"
[[ ! -e "$layer.part" ]] && pass "no .part left once the layer is in place" || fail ".part left"
[[ "$(cat "$Q/registered.1" 2>/dev/null)" == matrix-provision-*.json && "$(cat "$Q/registered.2" 2>/dev/null)" == matrix-[0-9]*.json ]] \
  && grep -q -- '^-pidfile$' "$Q/argv.2" \
  && pass "both boots were registered for mandu reap while they ran (qemu -pidfile)" || fail "registered: $(cat "$Q"/registered.* 2>&1 | tr '\n' ' ')"
[[ -z "$(ls -A "$MANDU_RUNTIME_DIR/vm-guests" 2>/dev/null)" ]] && pass "…and left the registry when they stopped" || fail "registry left: $(ls "$MANDU_RUNTIME_DIR/vm-guests")"
snap_run again "$C1" provisioned
[[ $RC -eq 0 && $BOOTS -eq 1 && "$LOGTXT" == *"provisioned layer cached"* ]] && pass "second run reuses the cached layer (one boot)" \
  || fail "again: rc=$RC boots=$BOOTS"
touch -d '10 days ago' "$layer"
snap_run stale "$C1" provisioned
[[ $RC -eq 0 && $BOOTS -eq 2 ]] && pass "a layer older than MANDU_VM_LAYER_MAX_AGE_DAYS is rebuilt" || fail "stale: rc=$RC boots=$BOOTS"
C2="$WORK/cache2"
snap_run broken "$C2" "fail: provisioning: packages missing"
[[ $RC -eq 0 && $BOOTS -eq 2 && -z "$(ls "$C2"/provisioned-* 2>/dev/null | grep -v '\.lock$')" && "$LOGTXT" == *"provisions itself"* ]] \
  && pass "a failed provisioning boot leaves no layer and the run provisions itself (a warning, not a FAIL)" \
  || fail "broken: rc=$RC boots=$BOOTS left=$(ls "$C2")"
grep -q -- "-b $C2/base.img " "$Q/img.log" && pass "…and that run sits on the base image" || fail "broken backing: $(cat "$Q/img.log")"
C3="$WORK/cache3"
snap_run off "$C3" provisioned MANDU_VM_SNAPSHOT=0
[[ $RC -eq 0 && $BOOTS -eq 1 ]] && grep -q -- "-b $C3/base.img " "$Q/img.log" \
  && pass "MANDU_VM_SNAPSHOT=0: no layer, the run sits on the base image" || fail "off: rc=$RC boots=$BOOTS"

# ── 4. the manual lane: --interactive (os-test-matrix.md §10.5 item 3) ────
render_suite __interactive__ "$WORK/iv" "$SB/qemu-img"   # any file stands in for a pubkey
G="$WORK/iv/guest-runner.sh"
i_line="$(grep -n '^if \[\[ "\$SUITE" == __interactive__ \]\]; then' "$G" | cut -d: -f1)"
s_line="$(grep -n '=== running suite' "$G" | cut -d: -f1)"
branch="$(sed -n "${i_line},/^fi\$/p" "$G")"
[[ -n "$i_line" && "$i_line" -lt "$s_line" && "$branch" == *'echo "interactive" > "$RESULT_FILE"'* && "$branch" != *finish* ]] \
  && pass "an interactive guest reports ready and stays up (no poweroff), before any suite runs" || fail "interactive branch: $branch"
d="$WORK/snap-inter"; mkdir -p "$d/matrix/suites" "$d/run" "$d/q"
printf '#!/bin/bash\n# deps:\n' > "$d/matrix/suites/s.sh"
LOGTXT="$(
  PATH="$SB:$PATH" QSTUB_DIR="$d/q" MANDU_VM_CACHE="$C1" MANDU_VM_SNAPSHOT=0 bash -c '
    source "'"$MATRIX"'/lib/common.sh"; source "'"$MATRIX"'/lib/qemu.sh"
    MATRIX_DIR="'"$d"'/matrix" REPO_ROOT="'"$d"'" TARGET_NAME=t RUN_WORK="'"$d"'/run"
    IMAGE_URL=http://x/base.img IMAGE_SHA256="" CPUS=1 MEM=64 TIMEOUT=60 LABELS=l SYSCTLS=""
    executor_interactive s' 2>&1
)"; RC=$?
fwd="$(grep -o 'hostfwd=[^,]*' "$d/q/argv.1" 2>/dev/null)"
port="$(sed -n 's/^hostfwd=tcp:127\.0\.0\.1:\([0-9]*\)-:22$/\1/p' <<<"$fwd")"
[[ $RC -eq 0 && -n "$port" ]] && pass "ssh is forwarded from a LOOPBACK port only ($fwd)" || fail "interactive: rc=$RC fwd='$fwd'; $(tail -4 <<<"$LOGTXT")"
[[ "$LOGTXT" == *"ssh -i $d/run/ssh/id_ed25519 -p $port "*"ubuntu@127.0.0.1"* ]] && pass "prints the ssh line with the run's key and port" || fail "no ssh line: $LOGTXT"
[[ "$(cat "$d/q/registered.1" 2>/dev/null)" == matrix-interactive-*.json && -z "$(ls -A "$MANDU_RUNTIME_DIR/vm-guests" 2>/dev/null)" ]] \
  && pass "the interactive guest (no timeout at all) was registered for mandu reap, and left the registry when it stopped" \
  || fail "interactive registration: $(cat "$d/q/registered.1" 2>&1); left: $(ls "$MANDU_RUNTIME_DIR/vm-guests" 2>&1)"
[[ -f "$d/run/ssh/id_ed25519" && "$(stat -c %a "$d/run/ssh/id_ed25519")" == 600 ]] && pass "a fresh key per run, mode 600" || fail "key: $(ls -la "$d/run/ssh" 2>&1)"
grep -qF "  - $(cat "$d/run/ssh/id_ed25519.pub")" "$d/run/seed/user-data" && grep -q '^ssh_pwauth: false$' "$d/run/seed/user-data" \
  && pass "user-data authorizes exactly that key and turns password login off" || fail "user-data ssh: $(grep -n ssh "$d/run/seed/user-data")"
out="$(FRESH_INSTALL_LIVE=1 bash "$MATRIX/run.sh" --interactive ubuntu-2404 fresh-install 2>&1)"; rc=$?
[[ $rc -eq 2 && "$out" == *"--keep-credential"* ]] && pass "--interactive with the live leg is refused without --keep-credential" || fail "live+interactive: rc=$rc $out"
out="$(FRESH_AGENTS_LIVE=1 bash "$MATRIX/run.sh" --keep ubuntu-2404 fresh-agents 2>&1)"; rc=$?
[[ $rc -eq 2 && "$out" == *"--keep-credential"* ]] && pass "--keep with a live leg is refused without --keep-credential" || fail "live+keep: rc=$rc $out"
out="$(MANDU_MATRIX_RECORD=0 bash "$MATRIX/run.sh" --interactive host 2>&1)"; rc=$?
[[ $rc -eq 2 && "$out" == *"has no --interactive"* ]] && pass "an executor without the manual lane says so (exit 2)" || fail "host interactive: rc=$rc $out"

echo; echo "matrix-provision: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
