# Contributing

Bug reports, false positives and detection gaps are the most useful things you can send. Code is welcome too. A few rules keep the project what it is.

## Ground rules

- **Standard library only.** A pull request that adds a `require` line to `go.mod` will be closed, however good the library is. The whole point of this agent is that the dependency surface is this repository and the Go toolchain.
- **One change per pull request.** One detector, one fix, one deployment tweak. Small PRs get reviewed; big ones wait.
- **Every detector change ships with a test.** Detectors are plain functions over parsed input, so tests run without root and without a real host. Look at `internal/detect/*_test.go` for the pattern.
- **Attacker-controlled strings go through the sanitizer.** Usernames, process names, paths and command lines are never formatted into output directly. See `Truncate` in `internal/engine`.
- **Keep the footprint.** The target is a 2 GB Pi. No goroutine per file, no polling faster than the defaults without a reason in the PR description, no new always-on work.
- **Document what it does not see.** If your change has a blind spot, add it to Limitations in the README. Honest limits are a feature.

## Local checks

```bash
gofmt -l .
go vet ./...
staticcheck ./...
go test -race ./...
make dist
```

No Go on the box? The checks run the same way inside the official image:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.27-alpine sh -c 'gofmt -l . && go vet ./... && go test ./...'
```

CI runs the same steps plus `govulncheck`, on x86 and on a native arm64 runner.

## Adding or changing a rule

Rules live in `deploy/rules/default.json`; copy it over `internal/rules/default.json` after editing (a test fails if they drift). The format is in [docs/rule-schema.md](docs/rule-schema.md).

Every rule needs at least one fixture it fires on and one it stays quiet on, in `internal/rules/testdata/rules/<rule-id>/positive/` and `negative/`. Take negatives from normal activity on a real box (apt upgrades, k3s pod churn, cron, backups) with hostnames, users and addresses scrubbed. `go test ./internal/rules/...` replays them and fails when either kind is missing.

## Proving a detector on a real host

After the learning period, `sudo ./scripts/simulate-attacks.sh` fires harmless stand-ins for eight categories and cleans up after itself.

No root, or no spare host? `make sim` does the same eight categories inside a container and needs only Docker. It builds the binary in `golang:1.27-alpine`, runs the agent in a `python:3-slim` container with file-mode logs and short intervals, fires the stand-ins from [scripts/sim-container/sim.sh](scripts/sim-container/sim.sh), writes `events.jsonl`, `report.json`, `metrics.txt` and `top10.json` to an output directory, and exits non-zero unless all eight categories fired.

If you add a category, add a step to both `scripts/sim-container/sim.sh` and `scripts/simulate-attacks.sh`.

## Fuzzing

Log lines, `/proc` fields, file names and rule files are attacker controlled and a root process parses them. Each parser has a native Go fuzz target; `make fuzz` runs them all (`FUZZTIME=10m make fuzz` for a longer pass). If you add a parser, add a target to the `FUZZ_TARGETS` list in the Makefile and the matrix in `.github/workflows/fuzz.yml`. A crasher is written to `<pkg>/testdata/fuzz/<target>/`; commit it with the fix and plain `go test` replays it from then on.

## Alert rules

Edit `deploy/prometheus/pisentry-rules.yaml`, copy its `groups:` into the `spec:` of `deploy/kubernetes/apps/base/pisentry/prometheusrule.yaml` indented two spaces (`go test ./internal/metrics` fails if they drift or reference a metric that does not exist), and add a case to `pisentry-rules.test.yaml`. Check with:

```bash
docker run --rm --entrypoint promtool -v "$PWD/deploy/prometheus:/r:ro" -w /r prom/prometheus:v3.7.3 test rules pisentry-rules.test.yaml
```

## README demos

The GIFs in the README are real recordings made by `make demo`; see [scripts/demo/README.md](scripts/demo/README.md). Re-record them when the output they show changes.

## Commit messages

Short imperative subject with an area prefix, and a body that says why:

```
detect: treat memfd-backed executables as hot processes

A miner started from memfd_create never has a path under /tmp, so the
existing "running from /tmp" rule missed it. ...
```

Prefixes in use: `detect`, `engine`, `audit`, `report`, `metrics`, `alert`, `deploy`, `ci`, `docs`.

## Reporting problems

- Bugs, false positives and detection gaps: open an issue with the matching template
- Security vulnerabilities: never a public issue. See [SECURITY.md](SECURITY.md)
