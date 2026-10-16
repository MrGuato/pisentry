## What and why

<!-- One change per PR. Say what attacker behavior or bug this is about, not just what the code does. -->

## Checklist

- [ ] No new entries in `go.mod`
- [ ] `gofmt -l .` is empty, `go vet ./...` and `staticcheck ./...` pass
- [ ] `go test -race ./...` passes and new detector logic has a test
- [ ] Attacker-controlled strings go through the engine sanitizer
- [ ] README updated if behavior, config keys, metrics or Limitations changed
- [ ] `CHANGELOG.md` has an entry under Unreleased
