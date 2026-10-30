package rules

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// pipeShell matches the built-in PS04-SUDO-PIPE-SHELL rule. Every reader in
// the concurrency test evaluates it, so a reload that ever exposed an empty
// or half-built rule set would show up as a missed match.
func pipeShell(t *testing.T) *EvalInput {
	t.Helper()
	in, err := loadFixture(filepath.Join("testdata", "rules", "PS04-SUDO-PIPE-SHELL", "positive", "curl-pipe-bash.json"))
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func evilRule(id string) map[string]any {
	r := minimalRule()
	r["id"] = id
	return r
}

func newLive(t *testing.T, dir string) *Live {
	t.Helper()
	eng, err := LoadOrDefault(dir)
	if err != nil {
		t.Fatal(err)
	}
	return NewLive(dir, eng)
}

func TestLiveReloadSwapsOnSuccess(t *testing.T) {
	dir := t.TempDir()
	l := newLive(t, dir)
	before := len(l.Get().Rules())

	writeFile(t, dir, "local.json", bundleJSON(t, evilRule("LOCAL-EVIL")))
	eng, err := l.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(eng.Rules()); got != before+1 {
		t.Fatalf("rules after reload = %d, want %d", got, before+1)
	}
	if l.Get() != eng {
		t.Fatal("Get does not return the reloaded engine")
	}
	if _, ok := l.Get().RuleByID("LOCAL-EVIL"); !ok {
		t.Fatal("new rule not active")
	}
}

func TestLiveReloadKeepsPreviousOnError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "local.json", bundleJSON(t, evilRule("LOCAL-EVIL")))
	l := newLive(t, dir)
	good := l.Get()

	writeFile(t, dir, "local.json", []byte(`{"schema_version": 1, "rules": [`))
	eng, err := l.Reload()
	if err == nil {
		t.Fatal("want error for a truncated bundle")
	}
	if eng != good || l.Get() != good {
		t.Fatal("a rejected reload replaced the active rule set")
	}
	if len(l.Get().Rules()) == 0 {
		t.Fatal("agent left with zero rules")
	}
	if _, ok := l.Get().RuleByID("LOCAL-EVIL"); !ok {
		t.Fatal("previous operator rule lost")
	}
}

func TestLiveStartsFromDefaultWhenDirBroken(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bad.json", []byte(`not json`))
	if _, err := LoadOrDefault(dir); err == nil {
		t.Fatal("want error")
	}
	// cmd/pisentry falls back to Default() exactly like this.
	l := NewLive(dir, Default())
	if _, err := l.Reload(); err == nil {
		t.Fatal("want error on reload of a still-broken dir")
	}
	if len(l.Get().Rules()) == 0 {
		t.Fatal("zero rules after a failed reload")
	}
}

func TestLiveWatchReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	l := newLive(t, dir)
	results := make(chan ReloadResult, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Watch(ctx, nil, 10*time.Millisecond, 30*time.Millisecond, func(r ReloadResult) { results <- r })

	writeFile(t, dir, "local.json", bundleJSON(t, evilRule("LOCAL-EVIL")))
	r := waitResult(t, results)
	if r.Err != nil || r.Trigger != "watch" {
		t.Fatalf("got %+v", r)
	}
	if _, ok := l.Get().RuleByID("LOCAL-EVIL"); !ok {
		t.Fatal("watch did not activate the new rule")
	}
	// No change, no reload.
	select {
	case r := <-results:
		t.Fatalf("unexpected reload without a change: %+v", r)
	case <-time.After(150 * time.Millisecond):
	}
}

// A Kubernetes ConfigMap volume exposes name.json -> ..data/name.json and
// updates by repointing the ..data symlink. The file names never change.
func TestLiveWatchFollowsConfigMapSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	v1 := filepath.Join(dir, "..2026_10_30_v1")
	v2 := filepath.Join(dir, "..2026_10_30_v2")
	for _, d := range []string{v1, v2} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, v1, "local.json", bundleJSON(t, evilRule("CM-V1")))
	writeFile(t, v2, "local.json", bundleJSON(t, evilRule("CM-V2")))
	if err := os.Symlink(filepath.Base(v1), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "local.json"), filepath.Join(dir, "local.json")); err != nil {
		t.Fatal(err)
	}
	l := newLive(t, dir)
	if _, ok := l.Get().RuleByID("CM-V1"); !ok {
		t.Fatal("v1 not loaded")
	}

	results := make(chan ReloadResult, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Watch(ctx, nil, 10*time.Millisecond, 30*time.Millisecond, func(r ReloadResult) { results <- r })

	// Atomic swap, as the kubelet does it: new link, then rename over ..data.
	tmp := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink(filepath.Base(v2), tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if r := waitResult(t, results); r.Err != nil {
		t.Fatal(r.Err)
	}
	if _, ok := l.Get().RuleByID("CM-V2"); !ok {
		t.Fatal("symlink swap not picked up")
	}
}

func TestLiveWatchCoalescesSignalBurst(t *testing.T) {
	dir := t.TempDir()
	l := newLive(t, dir)
	hup := make(chan os.Signal, 1)
	var reloads atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Watch(ctx, hup, 0, 50*time.Millisecond, func(r ReloadResult) {
		if r.Trigger != "signal" {
			t.Errorf("trigger = %q", r.Trigger)
		}
		reloads.Add(1)
	})
	for i := 0; i < 10; i++ {
		select {
		case hup <- syscall.SIGHUP:
		default: // signal.Notify drops too when the buffer is full
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if n := reloads.Load(); n != 1 {
		t.Fatalf("reloads = %d, want 1 for one burst", n)
	}
}

// No dropped events under load: readers evaluate a built-in rule on every
// iteration while reloads, good and bad, swap the set. Run with -race.
func TestLiveReloadUnderLoadDropsNothing(t *testing.T) {
	dir := t.TempDir()
	l := newLive(t, dir)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var evals, misses atomic.Int64
	for i := 0; i < 8; i++ {
		in := pipeShell(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				evals.Add(1)
				hit := false
				for _, r := range l.Get().Eval(in) {
					if r.ID == "PS04-SUDO-PIPE-SHELL" {
						hit = true
					}
				}
				if !hit {
					misses.Add(1)
				}
			}
		}()
	}
	good := bundleJSON(t, evilRule("LOCAL-EVIL"))
	bad := []byte(`{"schema_version": 1, "rules": [{"id": "X"}]}`)
	for i := 0; i < 50; i++ {
		if i%3 == 2 {
			writeFile(t, dir, "local.json", bad)
		} else {
			writeFile(t, dir, "local.json", good)
		}
		_, _ = l.Reload()
	}
	close(stop)
	wg.Wait()
	if evals.Load() == 0 {
		t.Fatal("readers never ran")
	}
	if m := misses.Load(); m != 0 {
		t.Fatalf("%d of %d evaluations missed a built-in rule during reloads", m, evals.Load())
	}
}

func TestFingerprint(t *testing.T) {
	dir := t.TempDir()
	empty, err := Fingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "a.json", []byte(`{}`))
	one, _ := Fingerprint(dir)
	writeFile(t, dir, "a.json", []byte(`{ }`))
	edited, _ := Fingerprint(dir)
	writeFile(t, dir, ".hidden.json", []byte(`{}`))
	writeFile(t, dir, "notes.txt", []byte(`x`))
	ignored, _ := Fingerprint(dir)
	missing, _ := Fingerprint(filepath.Join(dir, "nope"))
	if empty == one || one == edited {
		t.Fatal("content change not reflected")
	}
	if ignored != edited {
		t.Fatal("dotfiles and non-json files must not change the fingerprint")
	}
	if missing != "absent" {
		t.Fatalf("missing dir fingerprint = %q", missing)
	}
}

func waitResult(t *testing.T, ch <-chan ReloadResult) ReloadResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a reload")
		return ReloadResult{}
	}
}
