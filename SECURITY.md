# Security policy

pisentry runs as root under systemd, or with `hostPID` and three capabilities as a DaemonSet, on the host it protects. A vulnerability in pisentry is a vulnerability in that host. Please treat it that way, and so will I.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: [github.com/MrGuato/pisentry/security/advisories/new](https://github.com/MrGuato/pisentry/security/advisories/new).

Do not open a public issue, pull request or discussion for a suspected vulnerability.

Include what you can of:

- The version (`pisentry version`) and how it is deployed (systemd or DaemonSet, distro, kernel)
- The input that triggers it (a log line, a file name, a process name, a config), and whether it needs local access
- What the impact is: crash, hang, bypass, code execution, information disclosure
- A proof of concept if you have one. The container harness in `scripts/` is a safe place to build one

What to expect:

- Acknowledgement within 7 days
- A fix or a mitigation plan for High and Critical findings within 30 days of confirmation, and a release as soon as the fix is tested
- Credit in the release notes and the advisory, unless you ask to stay anonymous

## Supported versions

| Version | Supported |
|---|---|
| Latest 0.x release | Yes |
| Anything older | No, upgrade |

While the project is at 0.x, fixes land in the next release only. There are no backports.

## Scope

In scope:

- Crafted input that crashes, hangs or exhausts the agent: log lines, file names and contents under watched paths, `/proc` fields, command lines, config files
- Anything that makes the agent execute something, write outside its state and log directories, or read data it should not
- Suppressing, forging or hiding events in a way that is not already listed under Limitations in the README
- Escalation through the systemd unit, the DaemonSet grants, the HTTP endpoint or the webhook sender
- Release integrity: binaries, images, checksums, workflows

Out of scope, because it is documented behavior:

- A root user stopping the agent or editing its state. Ship events off the box; that is the defense
- Processes that live shorter than one poll interval
- Log-line forgery by local users in file mode (journald mode filters it with `ssh_require_root`)
- Detection thresholds you tuned in your own config
- Bugs in Falco, Prometheus, Grafana, ntfy or the kernel

## Threat model in one paragraph

Every input is attacker-controlled: log lines, file names and contents, process names and command lines from `/proc`. All of them pass through one sanitizer (control characters, terminal escapes, bidi overrides, invalid UTF-8, length) before they reach JSON, a webhook or a terminal. The agent opens no outbound connection except the webhook you configure, and it reads the webhook URL and token from the environment, never from the config file. It listens on `127.0.0.1:9817` by default. In Kubernetes it listens on the pod IP behind a NetworkPolicy that admits only the monitoring namespace, has no service account token, and runs on a read-only root filesystem. State lives in a root-only directory. The binary has no third-party code: `go.mod` has no `require` block, so the dependency surface is this repository and the Go toolchain.

## Supply chain

- Releases are built by GitHub Actions from version tags pushed by the maintainer, never from a laptop
- Binaries ship with `SHA256SUMS`. Verify with `sha256sum --check --ignore-missing SHA256SUMS`
- Images ship with SLSA provenance and an SBOM. Inspect with `docker buildx imagetools inspect ghcr.io/mrguato/pisentry:<tag> --format '{{json .Provenance}}'`
- Every GitHub Action is pinned to a commit SHA and every base image to a digest. Dependabot proposes the updates; a human merges them
- CI runs `govulncheck` against the Go standard library on every push, so a toolchain vulnerability fails the build instead of shipping
- Pin the image by digest in your cluster, not by tag
- Signature verification with cosign is on the roadmap and is not available yet. Until it is, the digest and the provenance attestation are the integrity check
