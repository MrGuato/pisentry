# pisentry reference

Commands, configuration, outputs, metrics and alerts. The [README](../README.md) is the overview; the rule format is in [rule-schema.md](rule-schema.md) and the event format in [event-schema.md](event-schema.md).

- [How it works](#how-it-works)
- [Commands](#commands)
- [Configuration](#configuration)
- [Outputs](#outputs)
- [Alerts](#alerts)
- [pisentry and Falco](#pisentry-and-falco)

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
- **One choke point for untrusted strings.** Usernames, process names, paths and command lines come from the attacker. They pass through one sanitizer (control characters, terminal escapes, bidi overrides, invalid UTF-8, length) before they reach JSON, a webhook or your terminal.

## Commands

```
pisentry run        [-config FILE]                  run the agent
pisentry report     [-since 24h] [-json]            ranked Top 10 from saved state
pisentry audit      [-json]                         one-shot posture audit, exit 2 on high/critical
pisentry baseline   reset                           re-learn baselines (the running agent picks it up)
pisentry check      [-rules PATH]                   validate rule bundles, exit 1 naming the file, rule and field
pisentry test-alert                                 send a test webhook
pisentry categories                                 print the Top 10 catalog
```

`pisentry audit` works without the agent running, which makes it handy for hardening a fresh Pi. `pisentry report -json` and `pisentry audit -json` are stable machine-readable output for evidence collection.

## Configuration

Every key is optional. See [deploy/config.example.json](../deploy/config.example.json) and [internal/config/config.go](../internal/config/config.go) for all of them. Unknown keys are rejected so typos fail loudly. The ones you are most likely to change:

| Key | Default | Notes |
|---|---|---|
| `learning_period` | `10m` | Re-learn with `pisentry baseline reset` after intentional changes |
| `cooldown` | `15m` | Same category and key will not re-fire inside this window |
| `ssh.fail_threshold` / `fail_window` | `5` / `5m` | |
| `ssh.allow_cidrs` | `[]` | e.g. `["192.168.1.0/24"]` to stop "new source" alerts from your LAN |
| `portscan.threshold` / `window` | `12` / `60s` | |
| `listeners.allow_ports` | `[]` | |
| `rules.dir` | `/etc/pisentry/rules.d` | Operator rule bundles over the built-in rules. Env `PISENTRY_RULES_DIR` |
| `rules.reload_interval` | `10s` | How often rules.d is checked for changes. `0s` turns the watch off; SIGHUP still reloads |
| `proc.allow_comm` | build tools, k3s, prometheus | Processes allowed to burn CPU |
| `fim.extra_watch` | `[]` | Add your own paths with a category and severity |
| `logs.source` | `auto` | `journald`, `file` or `none` |
| `logs.ssh_require_root` | `true` | Drops journald sshd records not logged by uid 0 (anti-forgery) |
| `alerts.type` | off | `ntfy`, `discord`, `slack`, `generic`. Also settable via `PISENTRY_ALERT_TYPE` |
| `alerts.min_severity` / `max_per_hour` | `high` / `30` | |
| `disable` | `[]` | Detector names: `auth`, `portscan`, `fim`, `listeners`, `proc`, `suid`, `audit` |

Secrets (webhook URL and token) are read from the environment, never from config.json.

## Outputs

**Event JSON** ([Event Schema v1](event-schema.json), [OCSF / ECS mapping](event-schema.md)), one per line on stdout:

```json
{"id":"c4f1d2e8-7a3b-4c91-8e2f-19a0b3c4d5e6","schema_version":1,"time":"2026-10-15T05:14:02Z","host":"kubepi",
 "category":"PS08","category_name":"Reverse shell","severity":"critical","mitre":["T1059.004"],"detector":"proc",
 "summary":"Reverse shell: bash (pid 5358) has fd 0 connected to 192.0.2.2:4445",
 "process":{"pid":5358,"ppid":1,"start_time":98112,"uid":0,"comm":"bash","exe":"/usr/bin/bash","cmdline":"bash -i"},
 "source":{"ip":"192.0.2.2","port":4445},"user":{"uid":0},
 "fields":{"pid":"5358","ppid":"1","comm":"bash","exe":"/usr/bin/bash","remote":"192.0.2.2:4445","fd":"0","uid":"0"}}
```

**Prometheus** on `:9817/metrics`:

| Metric | Type | Labels | Notes |
|---|---|---|---|
| `pisentry_events_total` | counter | `category`, `name`, `severity` | Pre-created at 0 so `increase()` sees the first event |
| `pisentry_category_last_event_timestamp_seconds` | gauge | `category` | |
| `pisentry_events_suppressed_total` | counter | `category` | Dropped by the per-key cooldown |
| `pisentry_audit_check_failing` | gauge | `check`, `category`, `severity` | 1 while a posture check fails |
| `pisentry_unexpected_listeners` | gauge | | Listening sockets not in the baseline right now |
| `pisentry_ssh_auth_failures_total` | counter | | |
| `pisentry_firewall_drop_lines_total` | counter | | Kernel log lines with SRC/DPT |
| `pisentry_detector_last_run_timestamp_seconds` | gauge | `detector` | Alert if it goes stale |
| `pisentry_detector_errors_total` | counter | `detector` | Check this after a deploy |
| `pisentry_alerts_sent_total` | counter | `type` | |
| `pisentry_alerts_dropped_total` | counter | `reason` | Rate limit or delivery error |
| `pisentry_log_lines_total` | counter | `source` | |
| `pisentry_baseline_entries` | gauge | `baseline` | |
| `pisentry_rules_loaded` | gauge | | Rules in the active set |
| `pisentry_rules_last_reload_timestamp_seconds` | gauge | | When the active set was loaded |
| `pisentry_rules_reload_failures_total` | counter | | Reloads rejected; the previous set stayed active |
| `pisentry_up`, `pisentry_build_info` | gauge | `host` / `version`, `goarch` | |

**HTTP API:** `GET /api/top10?window=24h` and `GET /api/events?limit=100` on the same listener.

**Webhooks:** ntfy (with priority mapping), Discord, Slack, or generic JSON. High and Critical by default. Alerts are rate limited to 30 per hour, and Critical alerts get their own budget so a flood of High events cannot hide a reverse shell.

## Alerts

The most important alert is the one the agent cannot send itself: an attacker with root stops the agent first. Prometheus alert rules ship in two forms with the same content:

- [deploy/prometheus/pisentry-rules.yaml](../deploy/prometheus/pisentry-rules.yaml) for a plain Prometheus (`rule_files:`), with unit tests in [pisentry-rules.test.yaml](../deploy/prometheus/pisentry-rules.test.yaml)
- [deploy/kubernetes/apps/base/pisentry/prometheusrule.yaml](../deploy/kubernetes/apps/base/pisentry/prometheusrule.yaml) for the Prometheus Operator, plus a Kubernetes-only alert for a node with no running agent (needs kube-state-metrics)

| Alert | Severity | Fires when |
|---|---|---|
| `PisentryAgentDown` | critical | A target stops answering scrapes for 5 minutes |
| `PisentryAgentAbsent` | critical | `pisentry_up` is gone from every target for 10 minutes |
| `PisentryNodeWithoutAgent` | critical | A Kubernetes node has had no reporting agent for 15 minutes |
| `PisentryCriticalEvent` | critical | Any critical event in the last 5 minutes |
| `PisentryHighEvents` | warning | Any high event in the last 15 minutes |
| `PisentryDetectorStale` | warning | proc, listeners or fim has not run for 10 minutes |
| `PisentryDetectorStaleSlow` | warning | The SUID walk or posture audit missed two 6-hour cycles |
| `PisentryDetectorErrors` | warning | A detector reported errors in the last 15 minutes |
| `PisentryAlertsDropped` | warning | Webhook alerts were rate limited or failed in the last hour |
| `PisentryRuleReloadFailed` | warning | A rules.d change was rejected |

Every alert carries a one-line `runbook` annotation. CI runs `promtool check rules`, `promtool test rules` and `kubeconform` against the CRD schema on every change.

## pisentry and Falco

| | Falco | pisentry |
|---|---|---|
| Signal | Syscalls via eBPF | Logs, /proc, file hashes |
| Strength | Container runtime behavior | SSH and auth abuse, posture, FIM, host persistence |
| Needs | Privileged pod, kernel eBPF support | Three capabilities, no kernel features |
| Footprint | 128Mi request | 24Mi request |

Falco sees a syscall the moment it happens. pisentry sees the things Falco does not try to cover.
