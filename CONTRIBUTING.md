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

## Proving a detector on a real host

After the learning period, `sudo ./scripts/simulate-attacks.sh` fires harmless stand-ins for eight categories and cleans up after itself. If you add a category, add a step to that script.

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
