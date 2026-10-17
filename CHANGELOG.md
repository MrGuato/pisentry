# Changelog

All notable changes to pisentry are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Container-based attack simulation (`make sim`, `scripts/sim-container/`): runs the agent in a `python:3-slim` container with file-mode logs and short detector intervals, fires harmless stand-ins for the eight simulatable categories, writes `events.jsonl`, `report.json`, `metrics.txt` and `top10.json`, and exits non-zero unless all eight fired. Proves detectors without root on a real host
- `docs/assets/grafana-top10.png`: the bundled Grafana dashboard rendered from the container simulation

### Changed

- Kubernetes manifests pin the image by release digest instead of by tag, and the staging overlay comment shows a digest override

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
