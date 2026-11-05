#!/usr/bin/env bash
# fixture-k3s.sh — the CI guest's k3s fixture (docs/design/testing/live-clients.md §3):
# a real one-node Kubernetes cluster OFF this machine, for the live kubectl
# and helm suite (integration.live-kube-clients). Installed by provision.sh
# as /usr/local/lib/mandu-ci/fixture-k3s.sh and run as root by boot.sh, before
# the pipeline, only when the job asks (vm-run.sh --fixture k3s, job.env
# MANDU_CI_FIXTURES=k3s):
#
#   fixture-k3s.sh <out-dir> <log-file>
#
#   1. a network namespace `mandu-k3s` joined to this one by a veth pair:
#      this side 10.201.0.1/24 (mk3s0), the cluster's node 10.201.0.2/24
#      (mk3s1). The node's address is no address of this machine, so the
#      session's egress proxy dials it as it would a cluster on the LAN (it
#      refuses this machine's own addresses: net-proxy blocked-destinations.ts);
#      10.0.0.0/8 is not in its always-denied set;
#   2. `k3s server` (K3S_VERSION, provision.sh) in that namespace, as a
#      transient systemd unit with its own delegated cgroup: the air-gap
#      images provision.sh placed in /var/lib/rancher/k3s/agent/images, so
#      pods start offline; traefik, servicelb, metrics-server, local-storage
#      and coredns off (the suite needs none);
#   3. ready = the API answers /readyz, the node is Ready, the default
#      service account exists and the air-gap busybox image is imported;
#   4. <out-dir>/admin.kubeconfig (k3s's admin: a client certificate of
#      system:masters, its server rewritten to https://10.201.0.2:6443),
#      <out-dir>/busybox-image (the image's name), then <out-dir>/ready, all
#      readable by `ci` (the guest is thrown away after the run).
#
# Why a root fixture and not a suite's own: the kubelet and containerd need
# real root (cgroups with the cpu controller, mounts, iptables), which no
# user namespace gives them in this guest. The cost: the cpu controller is on
# above the suites while it runs (boot.sh's "cpu" line warns), which is why
# only a run that asks starts it, never the nightly's drill guest.
#
# Exit 0 when ready; 1 (the log says why) otherwise. boot.sh logs either and
# runs the pipeline anyway: the suite SKIPs without <out-dir>/ready.
set -uo pipefail

OUT="${1:?usage: fixture-k3s.sh <out-dir> <log-file>}"
LOG="${2:?usage: fixture-k3s.sh <out-dir> <log-file>}"
NS=mandu-k3s
HOST_IF=mk3s0 NODE_IF=mk3s1
HOST_ADDR=10.201.0.1 NODE_ADDR=10.201.0.2
DATA=/var/lib/rancher/k3s
K3S_YAML=/etc/rancher/k3s/k3s.yaml
WAIT_S="${MANDU_CI_K3S_WAIT_S:-240}"

say() { echo "fixture-k3s: $*"; }
# kubectl from this side, with the admin kubeconfig rewritten to the node's
# address (k3s writes https://127.0.0.1:6443, the node's own loopback).
kc() { /usr/local/bin/kubectl --kubeconfig "$OUT/admin.kubeconfig" "$@"; }
publish_kubeconfig() {
  [[ -s "$K3S_YAML" ]] || return 1
  sed -E "s#server: https://(127\\.0\\.0\\.1|localhost|\\[::1\\]):6443#server: https://$NODE_ADDR:6443#" "$K3S_YAML" > "$OUT/admin.kubeconfig.tmp" \
    && grep -q "server: https://$NODE_ADDR:6443" "$OUT/admin.kubeconfig.tmp" \
    && mv "$OUT/admin.kubeconfig.tmp" "$OUT/admin.kubeconfig"
}

install -d -m 0755 "$OUT"
: > "$LOG"

ip netns add "$NS" || { say "ip netns add failed"; exit 1; }
ip link add "$HOST_IF" type veth peer name "$NODE_IF" || { say "veth failed"; exit 1; }
ip link set "$NODE_IF" netns "$NS"
ip addr add "$HOST_ADDR/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip -n "$NS" link set lo up
ip -n "$NS" addr add "$NODE_ADDR/24" dev "$NODE_IF"
ip -n "$NS" link set "$NODE_IF" up
ip -n "$NS" route add default via "$HOST_ADDR"
say "network: this side $HOST_ADDR ($HOST_IF), the node $NODE_ADDR ($NODE_IF in netns $NS)"

# nsenter --net only (not `ip netns exec`, which also unshares the mount
# namespace and remounts /sys): the kubelet and containerd share the host's
# mounts, as on a node.
if ! systemd-run --unit=mandu-k3s --collect --quiet -p Delegate=yes -p KillMode=mixed \
     -p "StandardOutput=append:$LOG" -p "StandardError=append:$LOG" \
     nsenter --net="/run/netns/$NS" -- /usr/local/bin/k3s server \
       --data-dir "$DATA" --node-ip "$NODE_ADDR" --advertise-address "$NODE_ADDR" \
       --tls-san "$NODE_ADDR" --flannel-iface "$NODE_IF" \
       --disable traefik,servicelb,metrics-server,local-storage,coredns \
       --write-kubeconfig "$K3S_YAML" --write-kubeconfig-mode 0600; then
  say "systemd-run k3s failed"; exit 1
fi

deadline=$((SECONDS + WAIT_S))
step() { say "waiting: $1"; }
ready=0
step "the API's /readyz"
while ((SECONDS < deadline)); do
  publish_kubeconfig && kc get --raw /readyz >/dev/null 2>&1 && { ready=1; break; }
  sleep 2
done
((ready)) || { say "the API did not answer /readyz in ${WAIT_S}s"; systemctl status mandu-k3s --no-pager 2>&1 | tail -5; exit 1; }
ready=0
step "the node Ready, the default service account, the busybox image"
img=""
while ((SECONDS < deadline)); do
  if kc get nodes -o 'jsonpath={.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -qx True \
     && kc -n default get serviceaccount default >/dev/null 2>&1; then
    img="$(/usr/local/bin/k3s crictl images -o json 2>/dev/null \
      | jq -r '.images[].repoTags[]? | select(test("mirrored-library-busybox:"))' 2>/dev/null | head -1)"
    [[ -n "$img" ]] && { ready=1; break; }
  fi
  sleep 2
done
((ready)) || { say "the node, the service account or the busybox image was not there in ${WAIT_S}s"; kc get nodes -o wide 2>&1 | tail -3; exit 1; }

printf '%s\n' "$img" > "$OUT/busybox-image"
chmod 0644 "$OUT/admin.kubeconfig" "$OUT/busybox-image"
touch "$OUT/ready"
say "ready in ${SECONDS}s: $(/usr/local/bin/k3s --version | head -1); node $NODE_ADDR; image $img"
exit 0
