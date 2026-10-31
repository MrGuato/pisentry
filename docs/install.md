# Installing pisentry

How to run pisentry as a hardened systemd service or as a Kubernetes DaemonSet managed by Flux. For a one-shot audit with nothing installed, see the [quick start](../README.md#quick-start).

## Bare metal (systemd)

```bash
git clone https://github.com/MrGuato/pisentry && cd pisentry
sudo ./deploy/install.sh                      # downloads the latest release for this CPU
sudo ./deploy/install.sh --version v0.1.0     # or a specific release
sudo ./deploy/install.sh --binary ./pisentry  # or a binary you built with make build
```

The installer puts the binary in `/usr/local/bin`, config in `/etc/pisentry/config.json`, secrets in `/etc/pisentry/pisentry.env` (mode 0600), and enables `pisentry.service`.

The unit runs as root because it has to read `/etc/shadow`, other users' `/proc/<pid>/fd` and the journal. Everything else is taken away: a two-capability bounding set, `ProtectSystem=strict`, `NoNewPrivileges`, a `@system-service` syscall filter, `MemoryDenyWriteExecute`, and a 256 MB memory cap (the process uses about 12 MB; the rest is room for kernel file cache that is charged to the unit). Read [deploy/systemd/pisentry.service](../deploy/systemd/pisentry.service) before you trust it.

To enable push alerts with ntfy, set `"type": "ntfy"` under `alerts` in config.json and put this in pisentry.env:

```
PISENTRY_WEBHOOK_URL=https://ntfy.sh/a-long-random-topic-name
```

Then run `sudo systemctl restart pisentry && sudo pisentry test-alert`.

## Kubernetes with Flux

`deploy/kubernetes/` mirrors the [pi-cluster](https://github.com/MrGuato/pi-cluster) layout:

```
deploy/kubernetes/
├── apps/base/pisentry/      namespace, configmap, daemonset, networkpolicy, podmonitor, prometheusrule, grafana dashboard
└── apps/staging/pisentry/   overlay + secret.yaml.example (SOPS-encrypt before committing)
```

There is no separate Flux Kustomization. pi-cluster's `apps` Kustomization points at `./apps/staging` with no root `kustomization.yaml`, so Flux already picks up every subdirectory. A second Kustomization for the same path would give the objects two owners.

1. Tag a release (`git tag -s v0.1.0 && git push origin v0.1.0`). The release workflow pushes `ghcr.io/mrguato/pisentry:v0.1.0` for arm64, arm/v7 and amd64 with provenance and an SBOM. New ghcr packages start private, so set it to public once, or add an imagePullSecret.
2. Pin the image by digest in the DaemonSet (`image: ghcr.io/mrguato/pisentry:v0.1.0@sha256:...`). This agent is root-equivalent on every node. A tag can move, a digest cannot.
3. Copy both paths into your cluster repo and merge to `main`. The `apps` Kustomization reconciles it. Kustomize applies atomically, so check `kubectl version` first: the DaemonSet uses `appArmorProfile` (1.30+). On an older API server that field fails the whole `apps` apply.
4. Optional alerts: copy `secret.yaml.example` to `secret.yaml`, fill it in, encrypt it with `sops --config clusters/staging/.sops.yaml --encrypt --in-place`, then uncomment it in the overlay.

```bash
kubectl -n pisentry get ds pisentry
kubectl -n pisentry exec ds/pisentry -- pisentry report
kubectl -n pisentry logs -l app.kubernetes.io/name=pisentry -f | jq 'select(.severity=="critical")'
```

The Grafana dashboard ("pisentry - Top 10 attacks") is loaded by the kube-prometheus-stack sidecar. It has severity stats, the ranked Top 10 bar gauge, events over time, failing posture checks, SSH failure rate per node, detector freshness, the pisentry alerts firing right now, and the active rule count.

The alert rules ship as a `PrometheusRule` next to the DaemonSet (see [Alerts](reference.md#alerts)), so the operator loads them with everything else.


### What the pod is allowed to do, and why

| Grant | Why |
|---|---|
| `hostPID: true` | See every host and pod process for miner and reverse-shell detection |
| `/` mounted read-only at `/host`, recursive where supported | FIM, posture audit, SUID walk, host journalctl |
| `CAP_DAC_READ_SEARCH` | Read /etc/shadow, journals, home directories |
| `CAP_SYS_PTRACE` | `readlink /proc/<pid>/fd` and `/exe` for other users' processes |
| `CAP_SYS_CHROOT` | Run the host's own journalctl so the journal format always matches |
| AppArmor Unconfined, SELinux `spc_t` | Ubuntu's default container profile blocks ptrace reads of host processes, and SELinux blocks host file reads on RHEL |
| `/var/lib/pisentry` hostPath, read-write | Per-node baselines survive pod restarts |

It is not a privileged pod, has no service account token, and has a read-only root filesystem. Know the blast radius anyway: if the agent itself were compromised, the attacker would effectively be root on the node. Every host security agent works this way. That is the reason for the stdlib-only code, the central sanitizing of attacker-controlled strings, the digest pin, and the NetworkPolicy that limits port 9817 to the monitoring namespace.
