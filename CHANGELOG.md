# Changelog

All notable changes to pisentry are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Release images are signed with cosign keyless signing by digest, and `SHA256SUMS` ships with a Sigstore bundle (`SHA256SUMS.sigstore.json`, requires cosign 3.0 or later). Verification steps are in SECURITY.md
- OpenSSF Scorecard workflow: weekly and on every push to main, results published to scorecard.dev and uploaded to code scanning. Badge in the README
- CodeQL analysis for Go on every push to main, every pull request and weekly, with results in code scanning. Badge in the README
- Container-based attack simulation (`make sim`, `scripts/sim-container/`): runs the agent in a `python:3-slim` container with file-mode logs and short detector intervals, fires harmless stand-ins for the eight simulatable categories, writes `events.jsonl`, `report.json`, `metrics.txt` and `top10.json`, and exits non-zero unless all eight fired. Proves detectors without root on a real host
- `docs/assets/grafana-top10.png`: the bundled Grafana dashboard rendered from the container simulation
- Project website at https://mrguato.github.io/pisentry/ (`site/`), built by `scripts/build-site.py` and published by the `pages` workflow. The roadmap and the live numbers are rendered from the GitHub API at build time, so the pages make no requests of their own and rebuild when a milestone or a roadmap issue changes

### Changed

- The SUID walk and the posture audit resume their 6 hour schedule after a restart instead of running again on every start. The last run time is saved with the baselines, so `pisentry baseline reset` still forces a fresh scan. On a Pi that kept restarting, the repeated walk filled the page and inode cache, and the agent's own reads stalled other workloads on the same SD card
- The SUID walk runs at idle disk priority so it yields to databases sharing the disk
- Memory cap 96 MiB -> 256 MiB in the systemd unit (`MemoryMax`) and the Kubernetes DaemonSet. The process still uses about 12 MB; both caps also count the kernel dentry/inode cache from the walks, and 96 MiB could be filled by that cache alone
- DaemonSet liveness probe: timeout 1s -> 5s, failureThreshold 3 -> 5, so a slow SD card does not get the agent killed
- README and website state the new cap, and the FAQ describes the v0.1.0 restart loop on a control-plane Pi
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
