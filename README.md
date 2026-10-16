# pisentry

A small host security agent for Raspberry Pi and other ARM Linux boxes. It watches for the ten attack patterns that actually hit small Linux hosts, ranks them, and tells you about it through Prometheus, JSON logs, a terminal report and push alerts.

- Single static Go binary, standard library only (no third-party modules)
- About 7 MB on disk and about 12 MB RSS. Tested on a 2 GB Pi profile at under 1% CPU
- arm64 (Pi 4/5), armv7 (32-bit Pi OS), amd64
- Runs as a hardened systemd service or as a Kubernetes DaemonSet managed by Flux
- Raspberry Pi OS, Ubuntu, Debian, RHEL-family (journald or classic syslog files)

```
$ sudo pisentry report
pisentry Top 10  |  host kubepi  |  last 24h  |  2026-10-15 14:02 EDT

#   ID    CATEGORY                 EVENTS  WORST     LAST SEEN  ALL TIME  MITRE
1   PS06  Cryptominer              2       critical  35s ago    2         T1496
2   PS07  Unexpected listener      2       critical  38s ago    2         T1571
3   PS02  Suspicious login         1       critical  40s ago    1         T1078
4   PS08  Reverse shell            1       critical  39s ago    1         T1059.004
5   PS01  SSH brute force          1       high      40s ago    1         T1110
6   PS04  Privilege escalation     1       high      40s ago    1         T1548.001,T1548.003
7   PS09  Port scan                1       high      40s ago    1         T1046
8   PS03  Insecure posture         1       medium    1m ago     1         T1078.001,T1021.004
9   PS05  Persistence              0       clean     -          0         T1053.003,T1543.002,...
10  PS10  Critical file tampering  0       clean     -          0         T1574.006,T1556.003,...
```

That output came from a real run against the bundled attack simulation.

## Why another agent

Falco, CrowdSec and Wazuh all run on ARM64, and you should use them where they fit. In this cluster pisentry is meant to run next to Falco, not instead of it:

| | Falco | pisentry |
|---|---|---|
| Signal | Syscalls via eBPF | Logs, /proc, file hashes |
| Strength | Container runtime behavior | SSH and auth abuse, posture, FIM, host persistence |
| Needs | Privileged pod, kernel eBPF support | Three capabilities, no kernel features |
| Footprint | 128Mi request | 24Mi request |

Falco sees a syscall the moment it happens. pisentry sees things Falco does not try to cover: a brute-force campaign in the auth log, a sudoers drop-in, a new `authorized_keys` entry, password auth left on, the `pi` user still having a password.

## The Top 10

| ID | Category | What triggers it | Source |
|---|---|---|---|
| PS01 | SSH brute force | 5 or more failed auths from one IP in 5 min (High). 20 or more is Critical | auth log |
| PS02 | Suspicious login | Success after 3 or more failures (Critical), direct root login (High), first login from a new source (Medium) | auth log |
| PS03 | Insecure posture | SSH password auth, root login, empty passwords, `pi` with a password, telnet/ftp, no auto-updates, weak sysctls | audit |
| PS04 | Privilege escalation | New SUID/SGID binary, sudoers change, user added to sudo/wheel/docker, `NOT in sudoers`, risky sudo commands | FIM, SUID walk, auth log |
| PS05 | Persistence | cron, systemd units (system and user), `authorized_keys`, rc.local, shell profiles, udev, motd, service account given a shell | FIM |
| PS06 | Cryptominer | Known miner names, stratum pool arguments, hot process running from /tmp, /dev/shm or a deleted binary, hot process connected to a pool port | /proc |
| PS07 | Unexpected listener | A socket listening that was not there during the learning period. Known backdoor ports are Critical | /proc/1/net |
| PS08 | Reverse shell | A shell or interpreter whose stdin, stdout or stderr is a TCP connection | /proc fd + net |
| PS09 | Port scan | One source hitting 12 or more distinct ports in 60s in firewall drop logs | kernel log |
| PS10 | Critical file tampering | passwd/shadow/group, PAM, sshd_config, `ld.so.preload`, new UID 0 account, new login account | FIM, audit |

Ranking is by severity-weighted score inside the window (critical 10, high 5, medium 2, low 1), then by count. Every category always shows, so the report reads as a status board even on a quiet day.

## How it works

```
 journald / auth.log / kern.log ─┐
                                 ├─> auth detector ─────┐
                                 └─> port-scan detector ┤
 /proc (every 15s) ──> miner + reverse-shell detector ──┤
 /proc/1/net (30s) ──> listener detector ───────────────┤
 /etc, /home, cron, systemd (60s) ──> FIM ──────────────┼─> engine ─┬─> state.json (baselines, Top 10 history)
 /usr, /tmp, /home (6h) ──> SUID walk ──────────────────┤  dedupe   ├─> /metrics  (Prometheus)
 sshd_config, shadow, sysctl (6h) ──> posture audit ────┘  sanitize ├─> stdout JSON (journald / kubectl logs)
                                                                    └─> webhook (ntfy, Discord, Slack, generic)
```

- **Learning period.** For the first 10 minutes (15 in Kubernetes) pisentry records listeners and login sources without alerting. FIM and SUID baselines are taken on the first scan. Baselines persist in `/var/lib/pisentry/state.json`.
- **Alert once, then adopt.** A changed file alerts once and the new hash becomes the baseline. A new listener alerts once and stays counted in `pisentry_unexpected_listeners` until it goes away or you re-baseline.
- **Cooldown.** The same category and key will not re-fire for 15 minutes, so one brute-force campaign is one alert.
- **Package manager awareness.** If apt/dpkg/dnf is running when a watched file changes, severity drops one level and the event says so.

## Install: bare metal (systemd)

```bash
git clone https://github.com/MrGuato/pisentry && cd pisentry
make dist                                  # or download from Releases
sudo ./deploy/install.sh --binary dist/pisentry-linux-arm64
```

The installer puts the binary in `/usr/local/bin`, config in `/etc/pisentry/config.json`, secrets in `/etc/pisentry/pisentry.env` (mode 0600), and enables `pisentry.service`.

To enable push alerts with ntfy, set `"type": "ntfy"` under `alerts` in config.json and put this in pisentry.env:

```
PISENTRY_WEBHOOK_URL=https://ntfy.sh/a-long-random-topic-name
```

Then run `sudo systemctl restart pisentry && sudo pisentry test-alert`.

## Install: Kubernetes with Flux

`deploy/kubernetes/` mirrors the pi-cluster layout:

```
deploy/kubernetes/
├── apps/base/pisentry/      namespace, configmap, daemonset, networkpolicy, podmonitor, grafana dashboard
└── apps/staging/pisentry/   overlay + secret.yaml.example (SOPS-encrypt before committing)
```

There is no separate Flux Kustomization on purpose. pi-cluster's `apps` Kustomization points at `./apps/staging` with no root `kustomization.yaml`, so Flux already picks up every subdirectory. Adding a second Kustomization for the same path would give the objects two owners.

1. Tag a release (`git tag v0.1.0 && git push origin v0.1.0`). The release workflow pushes `ghcr.io/mrguato/pisentry:v0.1.0` for arm64, arm/v7 and amd64. New ghcr packages start private, so set it to public once, or add an imagePullSecret.
2. Copy both paths into pi-cluster and merge to `main`. The `apps` Kustomization reconciles it. Kustomize applies atomically, so check `kubectl version` first: the DaemonSet uses `appArmorProfile` (1.30+). On an older API server that field fails the whole `apps` apply.
3. Optional alerts: copy `secret.yaml.example` to `secret.yaml`, fill it in, encrypt it with `sops --config clusters/staging/.sops.yaml --encrypt --in-place`, then uncomment it in the overlay.

```bash
kubectl -n pisentry get ds pisentry
kubectl -n pisentry exec ds/pisentry -- pisentry report
kubectl -n pisentry logs -l app.kubernetes.io/name=pisentry -f | jq 'select(.severity=="critical")'
```

The Grafana dashboard ("pisentry - Top 10 attacks") is loaded by the kube-prometheus-stack sidecar. It has severity stats, the ranked Top 10 bar gauge, events over time, failing posture checks, SSH failure rate per node, and detector freshness.

### What the pod is allowed to do, and why

| Grant | Why |
|---|---|
| `hostPID: true` | See every host and pod process for miner and reverse-shell detection |
| `/` mounted read-only at `/host`, recursive where supported | FIM, posture audit, SUID walk, host journalctl |
| `CAP_DAC_READ_SEARCH` | Read /etc/shadow, journals, home directories |
| `CAP_SYS_PTRACE` | `readlink /proc/<pid>/fd` and `/exe` for other users' processes |
| `CAP_SYS_CHROOT` | Run the host's own journalctl so the journal format always matches |
| AppArmor Unconfined, SELinux `spc_t` | Ubuntu's default container profile blocks ptrace reads of host processes, and SELinux blocks host file reads on RHEL (kubethink) |
| `/var/lib/pisentry` hostPath, read-write | Per-node baselines survive pod restarts |

It is not a privileged pod, has no service account token, and has a read-only root filesystem. Be clear on the blast radius anyway: if the agent itself were compromised, the attacker would effectively be root on the node. Every host security agent works this way. That is the reason for the stdlib-only code, the central sanitizing of attacker-controlled strings, and the NetworkPolicy that limits port 9817 to the monitoring namespace.

## Commands

```
pisentry run        [-config FILE]                  run the agent
pisentry report     [-since 24h] [-json]            ranked Top 10 from saved state
pisentry audit      [-json]                         one-shot posture audit, exit 2 on high/critical
pisentry baseline   reset                           re-learn baselines (the running agent picks it up)
pisentry test-alert                                 send a test webhook
pisentry categories                                 print the Top 10 catalog
```

`pisentry audit` works without the agent running, which makes it handy for hardening a fresh Pi:

```
FAIL    high      SSH-02  SSH root login permitted       PermitRootLogin yes
FAIL    medium    SSH-01  SSH password authentication enabled
...
How to fix:
  SSH-02: Set 'PermitRootLogin no' (or prohibit-password if you need key-based root).
```

## Outputs

**Event JSON**, one per line on stdout:

```json
{"time":"2026-10-15T05:14:02Z","host":"kubepi","category":"PS08","category_name":"Reverse shell",
 "severity":"critical","mitre":["T1059.004"],"detector":"proc",
 "summary":"Reverse shell: bash (pid 5358) has fd 0 connected to 192.0.2.2:4445",
 "fields":{"pid":"5358","ppid":"1","comm":"bash","exe":"/usr/bin/bash","remote":"192.0.2.2:4445","fd":"0","uid":"0"}}
```

**Prometheus** on `:9817/metrics`:

| Metric | Type |
|---|---|
| `pisentry_events_total{category,name,severity}` | counter, pre-created at 0 so `increase()` sees the first event |
| `pisentry_audit_check_failing{check,category,severity}` | gauge |
| `pisentry_unexpected_listeners` | gauge |
| `pisentry_ssh_auth_failures_total`, `pisentry_firewall_drop_lines_total` | counter |
| `pisentry_detector_last_run_timestamp_seconds{detector}` | gauge, alert if it goes stale |
| `pisentry_alerts_sent_total`, `pisentry_alerts_dropped_total{reason}` | counter |
| `pisentry_up`, `pisentry_build_info` | gauge |

**HTTP API:** `GET /api/top10?window=24h` and `GET /api/events?limit=100`.

**Webhooks:** ntfy (with priority mapping), Discord, Slack, or generic JSON. High and Critical by default. Alerts are rate limited to 30 per hour, and Critical alerts get their own separate budget so a flood of High events cannot hide a reverse shell.

## Prove it works

After the learning period:

```bash
sudo ./scripts/simulate-attacks.sh
```

This fires PS01, 02, 04, 05, 06, 07, 08 and 09 with harmless stand-ins: fake log lines from documentation IP ranges, a copy of `sleep` named xmrig, a reverse shell to the host's own IP, and a comment-only cron file. Everything is cleaned up when the script exits.

## Configuration

Every key is optional. See `deploy/config.example.json` and `internal/config/config.go` for all of them. Unknown keys are rejected so typos fail loudly. The ones you are most likely to change:

| Key | Default | Notes |
|---|---|---|
| `learning_period` | `10m` | Re-learn with `pisentry baseline reset` after intentional changes |
| `ssh.fail_threshold` / `fail_window` | `5` / `5m` | |
| `ssh.allow_cidrs` | `[]` | e.g. `["192.168.1.0/24"]` to stop "new source" alerts from your LAN |
| `portscan.threshold` / `window` | `12` / `60s` | |
| `listeners.allow_ports` | `[]` | |
| `proc.allow_comm` | build tools, k3s, prometheus | Processes allowed to burn CPU |
| `logs.source` | `auto` | `journald`, `file` or `none` |
| `logs.ssh_require_root` | `true` | Drops journald sshd records not logged by uid 0 (anti-forgery) |
| `alerts.type` | off | `ntfy`, `discord`, `slack`, `generic`. Also settable via `PISENTRY_ALERT_TYPE` |
| `disable` | `[]` | Detector names: `auth`, `portscan`, `fim`, `listeners`, `proc`, `suid`, `audit` |

## Limitations

- **Polling, not syscalls.** A process that lives less than one poll interval (15s) can be missed. Falco covers that gap.
- **Port scans need firewall logging.** pisentry reads kernel drop logs. It does not capture packets. Turn on `ufw logging on`, or `firewall-cmd --set-log-denied=all` on RHEL, or add an nftables `log` rule. Otherwise PS09 is blind.
- **Root wins.** An attacker who gets root can stop the agent or edit its state. Alert on `absent(pisentry_up)` and on stale `pisentry_detector_last_run_timestamp_seconds`, and ship events off the box (Prometheus, webhooks), which is the real defense.
- **Log forgery in file mode.** Any local user can write `sshd`-tagged lines with `logger`. With journald, `ssh_require_root` filters those out. Classic syslog files have no sender identity.
- **High UDP ports.** Unconnected UDP sockets on ports 32768 and up are skipped to avoid DNS-client noise, so a UDP backdoor on a high port will not show as a new listener.
- **FIM noise during upgrades.** Package installs touch watched paths. Severity drops one level while a package manager is running, but expect a few Low/Medium events after `apt upgrade`.
- **systemd hardening is strict.** If you point `output.json_file` outside `/var/log/pisentry`, add a `ReadWritePaths=` drop-in.
- **v0.1.** Tested with unit tests and live simulation in a Linux container, not yet across a fleet of real Pis. Check `pisentry_detector_errors_total` after deploying.

## Roadmap

- k3s module: privileged pods, hostPath mounts, kubelet anonymous auth
- `/dev/shm` and `memfd` execution as its own signal
- Optional inotify for instant FIM on supported kernels
- PrometheusRule alerts shipped with the manifests

## License

MIT
