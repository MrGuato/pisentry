# Changelog

All notable changes to pisentry are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Rules reload without a restart (#13): on SIGHUP (`systemctl reload pisentry`, the unit now has `ExecReload`) and when `rules.d` changes, checked every `rules.reload_interval` (default `10s`). The new set is validated in the background and swapped atomically; a broken file keeps the previous set active, logs the error and raises a High PS00 event. The directory is watched through symlinks so Kubernetes ConfigMap updates are seen, and a burst of changes is debounced into one reload. New metrics `pisentry_rules_loaded`, `pisentry_rules_last_reload_timestamp_seconds` and `pisentry_rules_reload_failures_total`
- Prometheus alert rules (#26): `deploy/prometheus/pisentry-rules.yaml` for a plain Prometheus and a `PrometheusRule` in the Kubernetes base. Agent down or absent, a node with no agent (Kubernetes), critical and high events, stale detectors (fast and slow tiers), detector errors, dropped alerts and rejected rule reloads, each with a one-line runbook annotation. `promtool` unit tests in `pisentry-rules.test.yaml`; CI runs `promtool check rules`, `promtool test rules` and `kubeconform` against the CRD schema. A Go test fails if the two copies drift or an alert references a metric that does not exist
- Grafana dashboard: "Firing pisentry alerts", "Rules loaded" and "Rule reloads rejected (24h)" panels
- Fuzz targets for every parser that reads attacker input (#32): syslog lines, journal JSON, `/proc/<pid>/stat`, `/proc/net/*`, the sanitizer (`engine.Truncate` properties), and the auth and port-scan matchers end to end through the engine with Event Schema v1 validation. `make fuzz`, 30 seconds per target on every pull request and 10 minutes per target weekly (`.github/workflows/fuzz.yml`)
- README demo GIFs recorded from real runs (`make demo`, `scripts/demo/`): live detection in a split terminal, the posture audit, and a rule hot reload. The Grafana screenshot is re-rendered with a real Prometheus evaluating the shipped alert rules
- Rule Schema v1 and a strict JSON rule loader (`internal/rules`, `docs/rule-schema.md`). Rules use Sigma-aligned field names, match on Event Schema v1 fields with literal operators kept apart from RE2 regex, and take per-rule exceptions by exe, parent comm, uid, user, container image, CIDR, path and command line. Unknown fields, duplicate IDs, bad regexes, unknown categories and oversize input are rejected, never truncated
- Built-in rules in `deploy/rules/default.json`, embedded in the binary: the eight risky-sudo patterns (`PS04-SUDO-*`) and the miner name and pool argument lists (`PS06-MINER-*`), each with an ID and MITRE techniques. Shell names, stratum ports, backdoor ports, the FIM watch list, GTFOBins SUID names, package managers and privileged groups move into the bundle's `catalog`. Events from a rule carry `rule.id`, `rule.title` and its techniques
- `rules.dir` (default `/etc/pisentry/rules.d`, env `PISENTRY_RULES_DIR`) loads operator bundles over the built-in rules. A rule with a built-in ID replaces it, which is how exceptions are added to a built-in rule. A broken bundle is logged at startup and the agent runs on the built-in rules
- `pisentry check [-rules PATH]` validates bundles and exits 1 naming the file, rule and field
- Process rules outside PS06 (for example from a rule pack) are reported under their own category, and rules can match on `process.uid` and `process.parent_comm`
- Per-rule positive and negative fixtures under `internal/rules/testdata/rules/<rule-id>/`, replayed by `go test` with no root. The test fails when a rule lacks either kind
- `FuzzLoadBytes` fuzz target for the rule loader
- Event Schema v1 (`docs/event-schema.json`, `docs/event-schema.md`): every event now carries `id` (UUIDv4), `schema_version` (`1`), and typed entity groups (`process`, `source`, `user`, `file`, `container`, `rule`), with OCSF and ECS mapping tables
- Release images are signed with cosign keyless signing by digest, and `SHA256SUMS` ships with a Sigstore bundle (`SHA256SUMS.sigstore.json`, requires cosign 3.0 or later). Verification steps are in SECURITY.md
- OpenSSF Scorecard workflow: weekly and on every push to main, results published to scorecard.dev and uploaded to code scanning. Badge in the README
- CodeQL analysis for Go on every push to main, every pull request and weekly, with results in code scanning. Badge in the README
- Container-based attack simulation (`make sim`, `scripts/sim-container/`): runs the agent in a `python:3-slim` container with file-mode logs and short detector intervals, fires harmless stand-ins for the eight simulatable categories, writes `events.jsonl`, `report.json`, `metrics.txt` and `top10.json`, and exits non-zero unless all eight fired. Proves detectors without root on a real host
- `docs/assets/grafana-top10.png`: the bundled Grafana dashboard rendered from the container simulation
- Project website at https://mrguato.github.io/pisentry/ (`site/`), built by `scripts/build-site.py` and published by the `pages` workflow. The roadmap and the live numbers are rendered from the GitHub API at build time, so the pages make no requests of their own and rebuild when a milestone or a roadmap issue changes

### Fixed

- A forged sshd log line with a port above 65535 produced an event with an out-of-range `source.port` that failed Event Schema v1 validation. Out-of-range ports are now dropped. Found by `FuzzAuthHandle`
- In file mode, a forged kernel firewall line with a `SRC=` that is not an address or a `DPT=` above 65535 could raise a PS09 event that failed Event Schema v1 validation. Such lines are now ignored. Found by `FuzzPortScanHandle` after 8 minutes
- The event `key` (the cooldown de-duplication key) was the one attacker-influenced string the sanitizer did not touch. The sudo detector keys on the command line, so a forged sudo log line produced a multi-kilobyte key with terminal escapes and invalid UTF-8, breaking Event Schema v1's 512-byte limit, and up to 5000 such keys could sit in the cooldown map. Keys are now sanitized and capped at 256 bytes, with a hash of the full key appended when cut so distinct commands still cool down separately. Found by `FuzzAuthHandle` after 10 minutes

### Changed

- `pisentry_events_total{category="PS00",severity="high"}` is pre-created at 0 like the Top 10 series, so `increase()` sees the first operational event. The dashboard's attack panels exclude PS00
- `proc.miner_names` now adds names on top of the `PS06-MINER-KNOWN-NAME` rule instead of replacing the built-in list, and its default is empty. `proc.stratum_ports` and `proc.shell_names` still replace the built-in lists when set
- The SUID walk and the posture audit resume their 6 hour schedule after a restart instead of running again on every start. The last run time is saved with the baselines, so `pisentry baseline reset` still forces a fresh scan. On a Pi that kept restarting, the repeated walk filled the page and inode cache, and the agent's own reads stalled other workloads on the same SD card
- The SUID walk runs at idle disk priority so it yields to databases sharing the disk
- Memory cap 96 MiB -> 256 MiB in the systemd unit (`MemoryMax`) and the Kubernetes DaemonSet. The process still uses about 12 MB; both caps also count the kernel dentry/inode cache from the walks, and 96 MiB could be filled by that cache alone
- DaemonSet liveness probe: timeout 1s -> 5s, failureThreshold 3 -> 5, so a slow SD card does not get the agent killed
- README and website state the new cap, and the FAQ describes the v0.1.0 restart loop on a control-plane Pi
- Kubernetes manifests pin the image by release digest instead of by tag, and the staging overlay comment shows a digest override

### Deprecated

- `v0.1.0` entity keys inside `fields` (`pid`, `ppid`, `comm`, `exe`, `cmdline`, `command`, `src_ip`, `port`, `user`, `uid`, `owner_uid`, `path`, `old_sha256`, `sha256`, `check`) are superseded by the typed entity groups (`process.*`, `source.*`, `user.*`, `file.*`, `rule.*`). They remain populated in `fields` through `v0.2.x` and will be removed in `v0.3.0`

## [0.1.0] - 2026-10-15

First release.

### Added

- Ten detection categories, PS01 to PS10: SSH brute force, suspicious login, insecure posture, privilege escalation, persistence, cryptominers, unexpected listeners, reverse shells, port scans, critical file tampering. Each event carries MITRE ATT&CK technique IDs
- Detectors for journald and classic syslog files, `/proc` polling, `/proc/1/net` listeners, file integrity with package-manager awareness, a SUID/SGID walk and a posture audit
- Learning period, persistent baselines, alert-once-then-adopt, per-key cooldown, and one sanitizer for every attacker-controlled string
- Outputs: ranked Top 10 terminal report, JSON events on stdout or to a file, Prometheus metrics on `:9817`, a small HTTP API, and webhooks for ntfy, Discord, Slack and generic JSON with rate limiting and a separate Critical budget
- Commands: `run`, `report`, `audit`, `baseline reset`, `test-alert`, `categories`
- Hardened systemd unit and an installer for Raspberry Pi OS, Ubuntu, Debian and RHEL-family hosts
- Distroless multi-arch image (arm64, armv7, amd64) with provenance and SBOM
- Flux-ready Kubernetes manifests: DaemonSet, NetworkPolicy, PodMonitor, Grafana dashboard
- Safe, self-cleaning attack simulation script

[Unreleased]: https://github.com/MrGuato/pisentry/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MrGuato/pisentry/releases/tag/v0.1.0
