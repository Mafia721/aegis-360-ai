---
name: Kubernetes & Container Security
description: Assess Kubernetes and Docker infra — exposed API server/kubelet/etcd, RBAC and SA-token abuse, dashboard/skip-login, and container-to-host escapes (docker.sock, privileged, capabilities, runc CVE-2024-21626).
tags: [kubernetes, docker, container-escape, rbac, misconfig, privesc]
recommended_tools: [curl, jq, python3, nmap_scan, nuclei_scan, execute_command]
vuln_classes: [misconfig]
domain: cloud
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/hunt-k8s/SKILL.md, infra/docker-privesc/SKILL.md]}
---
# Kubernetes & Container Security

Containerized infra fails at two boundaries: the **cluster control plane** (exposed/anonymous API server,
kubelet, etcd, dashboard) and the **container→host** boundary (privileged pods, mounted docker socket, excess
capabilities). Goal: enumerate what the current identity can actually do (RBAC-honest), and prove one concrete
impact (read a Secret, or escape to the node) within scope.

## When to use
Ports `6443/8443` (API server), `10250/10255` (kubelet), `2379/2380` (etcd) exposed; a dashboard on 30000-ish
NodePort; you have a shell inside a container; or cloud metadata reveals a K8s service account.

## Phase 1 — Fingerprint
```
nmap_scan -p 6443,8443,10250,10255,2379,2380,30000-32767 TARGET
curl -sk https://TARGET:6443/version          # API server (anonymous on many clusters)
curl -sk https://TARGET:10250/pods            # kubelet pod list (if read-open)
curl -s  http://TARGET:2379/version           # etcd unauth
```

## Phase 2 — API server access (RBAC-honest)
```
# The only honest privilege check:
kubectl auth can-i --list                      # what THIS identity may do
kubectl auth can-i get secrets -A
kubectl get pods,secrets,serviceaccounts -A    # only what's allowed
```
`system:anonymous` with any meaningful verb is a finding. If `can-i get secrets` is allowed, read ONE secret
to prove impact and **redact** its value before reporting.

## Phase 3 — Kubelet / etcd / dashboard
- **Kubelet 10250:** `/run/<ns>/<pod>/<container>` exec primitive (SPDY/WebSocket) can run commands in pods.
  Prove with `id` in a pod; don't pivot further than needed.
- **etcd 2379 unauth:** `etcdctl get / --prefix --keys-only` exposes every Secret/token in the cluster — a
  full compromise; prove with a key listing (redact values).
- **Dashboard skip-login / over-privileged SA:** unauthenticated dashboard or a dashboard SA with cluster-admin.

## Phase 4 — Service-account token abuse
In-pod token at `/var/run/secrets/kubernetes.io/serviceaccount/token` (+`ca.crt`, `namespace`). Use it against
the API server; check its **audience/expiry** (bound/projected tokens are scoped). A default SA with broad RBAC
is the common escalation.

## Phase 5 — Container → host escape
```
id                                             # docker group?
ls -la /var/run/docker.sock                    # mounted socket → host root
cat /proc/1/status | grep CapEff               # CAP_SYS_ADMIN / privileged?
```
Escape paths (only where authorized): mounted **docker.sock** → run a container mounting host `/`;
**privileged** pod/container → mount host disk or cgroup-release trick; excess **capabilities**
(`SYS_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH`); **runc/Leaky Vessels CVE-2024-21626** on unpatched runtimes.
Prove with a read of a host-only file (e.g. host `/etc/hostname` via the mount) — capture the exact steps.

## Validation gate
- API/etcd/kubelet: the actual command output proving access (secret listing redacted, or `id` in a pod).
- Escape: a host-context artifact you could only read after escaping (not just "privileged: true").
- RBAC claims must come from `auth can-i`, not assumption.

## Remediation (attach to findings)
Disable anonymous-auth on API server/kubelet; authn+TLS on etcd; least-privilege RBAC (no default-SA
cluster-admin, drop unused `secrets` verbs); never mount docker.sock into pods; drop privileged + trim
capabilities + read-only rootfs (PodSecurity/OPA); patch runc; restrict NodePort/dashboard exposure.
