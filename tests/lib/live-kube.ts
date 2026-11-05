/**
 * live-kube — the shared half of the live kubectl and helm suite
 * (docs/design/testing/live-clients.md §3): where the real cluster is, what
 * the suite needs from the host, and the case list.
 *
 * The cluster: an admin kubeconfig of a real cluster whose API server is
 * NOT on this machine (the session's egress proxy refuses this machine's own
 * addresses, net-proxy blocked-destinations.ts): MANDU_LIVE_KUBECONFIG, else
 * the CI guest's k3s fixture (scripts/ci/guest/fixture-k3s.sh, started by
 * `scripts/ci/vm-run.sh --fixture k3s`) at /run/mandu-ci-fixtures/k3s.
 *
 * PROVENANCE: NEW Mandu test code.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { isIP } from "node:net";
import { networkInterfaces } from "node:os";
import { join } from "node:path";

import type { LiveCase } from "./live-clients.js";

export const K3S_FIXTURE_DIR = "/run/mandu-ci-fixtures/k3s";

export interface LiveKube {
  /** The admin kubeconfig (the human's own, used outside the session to set up). */
  admin: string;
  /** The busybox image the cluster can start offline. */
  image: string;
}

/** The cluster, or the reason the suite SKIPs. */
export function liveKube(): LiveKube | string {
  const own = process.env["MANDU_LIVE_KUBECONFIG"];
  let admin: string;
  let image = process.env["MANDU_LIVE_KUBE_IMAGE"] ?? "";
  if (own) {
    if (!existsSync(own)) return `MANDU_LIVE_KUBECONFIG names no file (${own})`;
    admin = own;
  } else {
    if (!existsSync(join(K3S_FIXTURE_DIR, "ready"))) return `no cluster: set MANDU_LIVE_KUBECONFIG, or run in the CI guest with the k3s fixture (scripts/ci/vm-run.sh --fixture k3s; ${K3S_FIXTURE_DIR}/ready is absent)`;
    admin = join(K3S_FIXTURE_DIR, "admin.kubeconfig");
    if (!image && existsSync(join(K3S_FIXTURE_DIR, "busybox-image"))) image = readFileSync(join(K3S_FIXTURE_DIR, "busybox-image"), "utf8").trim();
  }
  if (!image) image = "busybox:1.37";
  for (const cmd of ["kubectl", "helm", "curl"]) {
    if (spawnSync("sh", ["-c", `command -v ${cmd}`], { stdio: "ignore" }).status !== 0) return `no ${cmd} on PATH`;
  }
  return { admin, image };
}

/** Is `host` an address of this machine (or a loopback name)? The proxy
 *  never dials one, so a cluster there cannot be the suite's. */
export function onThisMachine(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (isIP(h) === 0) return false;
  if (/^127\./.test(h) || h === "::1" || h === "0.0.0.0") return true;
  return Object.values(networkInterfaces()).some((as) => (as ?? []).some((a) => a.address.toLowerCase() === h));
}

/** The placeholder of the n-th `token:` of `~/.kube/config` (its twin). */
export const kubeTokenPlaceholder = (n = 1): string => `"$(sed -n 's/^ *token: *//p' ~/.kube/config | tr -d '"' | sed -n ${n}p)"`;

/** The cases. `ns` is the run's namespace; `server` the API's host:port; the
 *  decoy is a NodePort at `decoy` (host:port, plain HTTP) whose pod prints
 *  every request it gets. */
export function kubeCases(o: { ns: string; image: string; nodeHost: string; decoyPort: number; pfPort: number }): LiveCase[] {
  const pods = [
    "apiVersion: v1", "kind: Pod", "metadata: {name: ticker, labels: {app: ticker}}",
    "spec:", "  terminationGracePeriodSeconds: 0", "  containers:",
    `  - {name: c, image: "${o.image}", imagePullPolicy: IfNotPresent, command: [sh, -c, 'i=0; while true; do echo tick-$i; i=$((i+1)); sleep 1; done']}`,
    "---",
    "apiVersion: v1", "kind: Pod", "metadata: {name: web, labels: {app: web}}",
    "spec:", "  terminationGracePeriodSeconds: 0", "  containers:",
    `  - {name: c, image: "${o.image}", imagePullPolicy: IfNotPresent, command: [sh, -c, 'mkdir -p /www && echo hello-from-pod > /www/index.html && exec httpd -f -p 8080 -h /www']}`,
  ].join("\n");
  const chart = [
    "mkdir -p chart/templates",
    "printf 'apiVersion: v2\\nname: mdu-live\\nversion: 0.1.0\\n' > chart/Chart.yaml",
    "printf 'apiVersion: v1\\nkind: ConfigMap\\nmetadata:\\n  name: {{ .Release.Name }}-cm\\ndata:\\n  greeting: hello-from-helm\\n' > chart/templates/cm.yaml",
  ].join(" && ");
  return [
    { name: "kube-twin", cmd: "cat ~/.kube/config; echo; echo KUBECONFIG=$KUBECONFIG" },
    // The token's placeholder from curl at its own API server: put back
    // (the request's URL holds the server's address, which a kubeconfig's
    // §4 tripwire once took for a secret: live-clients.md §3.3).
    { name: "kube-token-own-api", cmd: `curl -sS --max-time 15 -H "Authorization: Bearer ${kubeTokenPlaceholder(1)}" https://${o.nodeHost}:6443/version; echo` },
    { name: "kube-whoami-token", cmd: "kubectl auth whoami -o jsonpath='{.status.userInfo.username}'; echo" },
    { name: "kube-whoami-cert", cmd: "kubectl --context cert auth whoami -o jsonpath='{.status.userInfo.username}'; echo" },
    { name: "kube-apply", cmd: `cat > pods.yaml <<'EOF'\n${pods}\nEOF\nkubectl apply -f pods.yaml` },
    { name: "kube-wait", cmd: "kubectl wait --for=condition=Ready pod/ticker pod/web --timeout=150s" },
    { name: "kube-get", cmd: "kubectl get pods -o name | sort" },
    { name: "kube-get-cert", cmd: `kubectl --context cert -n ${o.ns} get pods -o name | sort` },
    { name: "kube-watch", cmd: "timeout 6 kubectl get pods -w; true" },
    { name: "kube-logs-f", cmd: "timeout 15 kubectl logs -f ticker | head -3" },
    { name: "kube-exec", cmd: "kubectl exec web -- sh -c 'echo exec-ok $((6*7))'" },
    { name: "kube-exec-cert", cmd: `kubectl --context cert -n ${o.ns} exec web -- echo cert-exec-ok` },
    { name: "kube-exec-stdin", cmd: "printf 'from-stdin\\n' | kubectl exec -i web -- cat" },
    // port-forward: kubectl listens on this machine's loopback, and a client
    // OUTSIDE the agent's world (the test, as the user's browser would)
    // connects; kubectl relays it over the cluster's SPDY stream through the
    // session proxy. The case waits until kubectl says it handled one.
    {
      name: "kube-port-forward",
      cmd: `kubectl port-forward pod/web ${o.pfPort}:8080 > pf.log 2>&1 & PF=$!; for i in $(seq 1 120); do grep -q 'Handling connection' pf.log && break; sleep 0.25; done; sleep 1; kill $PF 2>/dev/null; cat pf.log; grep -q 'Handling connection' pf.log`,
    },
    // A program of the agent's own connecting to it is refused by the
    // session's connect rules, as for any loopback port that is not one of
    // the session's services (exec-routing.md §7.5, "a loopback dev server
    // is refused there unless a rule admits it").
    {
      name: "kube-port-forward-in-session",
      cmd: `kubectl port-forward pod/web ${o.pfPort + 1}:8080 > pf2.log 2>&1 & PF=$!; for i in $(seq 1 60); do grep -q Forwarding pf2.log && break; sleep 0.25; done; curl -sS --noproxy '*' --max-time 5 http://127.0.0.1:${o.pfPort + 1}/; r=$?; kill $PF 2>/dev/null; [ $r = 0 ]`,
    },
    { name: "helm-install", cmd: `${chart} && helm install mdu-live ./chart --wait --timeout 120s && kubectl get configmap mdu-live-cm -o jsonpath='{.data.greeting}'; echo` },
    { name: "helm-list", cmd: "helm list -o json" },
    { name: "helm-list-cert", cmd: `helm --kube-context cert -n ${o.ns} list -q` },
    // The token's placeholder anywhere but its own API server: the
    // kubelet's port (HTTPS) and a NodePort (plain HTTP) on the same node,
    // through the session proxy (HTTPS_PROXY / HTTP_PROXY in the agent's
    // environment): withheld.
    { name: "kube-token-kubelet", cmd: `curl -sS -o /dev/null -w 'code=%{http_code}\\n' --max-time 15 -H "Authorization: Bearer ${kubeTokenPlaceholder(1)}" https://${o.nodeHost}:10250/pods` },
    { name: "kube-token-decoy", cmd: `curl -sS --max-time 15 -H "Authorization: Bearer ${kubeTokenPlaceholder(1)}" http://${o.nodeHost}:${o.decoyPort}/token-decoy; echo; echo done` },
  ];
}
