#!/usr/bin/env bash
# openshell-cache.sh — prepare OpenShell's MicroVM driver image cache once, in
# the CI image (provision.sh, continuous-integration.md §9.10), so a drill
# run's sandboxes start from it and pull nothing:
#
#   openshell-cache.sh <bin dir> <vm state dir> <sandbox image@digest> <bootstrap image@digest>
#
# Runs as the CI user (the driver opens /dev/kvm: the user is in the kvm
# group). A throwaway gateway on loopback with the VM driver, its state in
# <vm state dir>, creates one sandbox from the pinned image (the driver pulls
# both images, checks each digest, and prepares the bootstrap and the image
# root disks), runs `true` in it, deletes it, and stops. What stays in
# <vm state dir> is `images/`: a run's gateway (the drill suite's
# baseline-openshell.ts) links its own state dir's `images` to it. Exit 0
# only when the sandbox ran.
set -euo pipefail
B="${1:?usage: openshell-cache.sh <bin dir> <vm state dir> <sandbox image> <bootstrap image>}"
VM="${2:?}" IMAGE="${3:?}" BOOT="${4:?}"
PORT=17699
T="$(mktemp -d /tmp/mdu-osc-XXXXXX)"
GW=""
cleanup() {
  [[ -n "$GW" ]] && kill "$GW" 2>/dev/null && wait "$GW" 2>/dev/null
  rm -rf "$T" "$VM/sandboxes" "$VM/run" "$VM/rootfs-tar-staging"
}
trap cleanup EXIT
export XDG_CONFIG_HOME="$T/config" XDG_STATE_HOME="$T/state" XDG_DATA_HOME="$T/data" XDG_CACHE_HOME="$T/cache"
export OPENSHELL_LOCAL_TLS_DIR="$T/tls" OPENSHELL_TELEMETRY_ENABLED=false DO_NOT_TRACK=1 OPENSHELL_GATEWAY=mdu-cache
# the VM driver formats its disks with mke2fs (e2fsprogs, in /usr/sbin)
export PATH="$B:$PATH:/usr/sbin:/sbin"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_STATE_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME"
openshell-gateway generate-certs --output-dir "$T/tls" --server-san 127.0.0.1 >/dev/null
cat > "$T/gateway.toml" <<EOF
[openshell]
version = 2

[openshell.gateway]
name = "mdu-cache"
bind_address = "127.0.0.1:$PORT"
compute_driver = "vm"
guest_tls_ca = "$T/tls/ca.crt"

[openshell.gateway.tls]
cert_path = "$T/tls/server/tls.crt"
key_path = "$T/tls/server/tls.key"
client_ca_path = "$T/tls/ca.crt"

[openshell.gateway.gateway_jwt]
signing_key_path = "$T/tls/jwt/signing.pem"
public_key_path = "$T/tls/jwt/public.pem"
kid_path = "$T/tls/jwt/kid"
gateway_id = "mdu-cache"

[openshell.gateway.mtls_auth]
enabled = true

[openshell.drivers.vm]
state_dir = "$VM"
driver_dir = "$B"
default_image = "$IMAGE"
bootstrap_image = "$BOOT"
vcpus = 2
mem_mib = 2048
overlay_disk_mib = 4096
EOF
openshell-gateway --config "$T/gateway.toml" > "$T/gateway.log" 2>&1 &
GW=$!
for _ in $(seq 1 120); do (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break; sleep 0.5; done
openshell gateway add "https://127.0.0.1:$PORT" --local --name mdu-cache >/dev/null
if ! openshell sandbox create --name cache --detach --no-tty --no-auto-providers || ! openshell sandbox exec -n cache --no-tty -- true; then
  echo "openshell-cache: the sandbox did not run; the gateway's last lines:"
  sed 's/\x1b\[[0-9;]*m//g' "$T/gateway.log" | grep -E 'WARN|ERROR|Error' | tail -20 | cut -c1-400
  exit 1
fi
openshell sandbox delete cache >/dev/null || true
# the deletion is asynchronous: wait for the VM to go before the gateway does
for _ in $(seq 1 60); do openshell sandbox get cache >/dev/null 2>&1 || break; sleep 1; done
ls "$VM/images"
echo "openshell-cache: $IMAGE and $BOOT prepared in $VM/images"
