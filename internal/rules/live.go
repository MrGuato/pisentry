package rules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Live holds the active rule set behind an atomic pointer so detectors can
// read it on every scan without locks while a reload swaps it underneath
// them. A reload compiles the whole set in the background and swaps only on
// success: a broken file keeps the previous set, so the agent never runs with
// zero rules.
type Live struct {
	dir string
	cur atomic.Pointer[Engine]

	mu   sync.Mutex // serializes reloads and guards seen
	seen string     // fingerprint of dir at the last reload attempt
}

// NewLive wraps an already loaded engine. initial must not be nil; pass
// Default() when the first load failed.
func NewLive(dir string, initial *Engine) *Live {
	l := &Live{dir: dir}
	l.cur.Store(initial)
	l.seen, _ = Fingerprint(dir)
	return l
}

// Get returns the active rule set. It is safe to call from any goroutine.
func (l *Live) Get() *Engine { return l.cur.Load() }

// Dir is the rules.d directory this set reloads from.
func (l *Live) Dir() string { return l.dir }

// Reload loads the built-in rules plus dir and swaps them in. On error the
// active set is left alone and the error is returned.
func (l *Live) Reload() (*Engine, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen, _ = Fingerprint(l.dir)
	eng, err := LoadOrDefault(l.dir)
	if err != nil {
		return l.cur.Load(), err
	}
	l.cur.Store(eng)
	return eng, nil
}

// changed reports whether dir differs from the last reload attempt.
func (l *Live) changed() bool {
	fp, err := Fingerprint(l.dir)
	if err != nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return fp != l.seen
}

// ReloadResult is passed to the Watch callback after every reload attempt.
type ReloadResult struct {
	Engine  *Engine // the active set after the attempt
	Err     error   // nil when the new set was swapped in
	Trigger string  // "signal" or "watch"
}

// Watch reloads when a value arrives on hup and, if poll is positive, when
// the contents of dir change. Changes are debounced: dir must stay the same
// for debounce before it is reloaded, so a burst of writes (an editor save, a
// ConfigMap ..data swap, a multi-file copy) is one reload. Bursts of signals
// coalesce the same way. Watch returns when ctx ends.
func (l *Live) Watch(ctx context.Context, hup <-chan os.Signal, poll, debounce time.Duration, done func(ReloadResult)) {
	var tick <-chan time.Time
	if poll > 0 {
		t := time.NewTicker(poll)
		defer t.Stop()
		tick = t.C
	}
	run := func(trigger string) {
		eng, err := l.Reload()
		if done != nil {
			done(ReloadResult{Engine: eng, Err: err, Trigger: trigger})
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			if !l.settle(ctx, hup, debounce) {
				return
			}
			run("signal")
		case <-tick:
			if !l.changed() {
				continue
			}
			if !l.settle(ctx, hup, debounce) {
				return
			}
			run("watch")
		}
	}
}

// settle waits until dir has not changed for d, draining extra signals so a
// burst of SIGHUPs is one reload. It returns false if ctx ended first.
func (l *Live) settle(ctx context.Context, hup <-chan os.Signal, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	last, _ := Fingerprint(l.dir)
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-hup:
		case <-t.C:
			fp, _ := Fingerprint(l.dir)
			if fp == last {
				return true
			}
			last = fp
			t.Reset(d)
		}
	}
}

// Fingerprint hashes the names and contents of the rule files in dir. Files
// are read through symlinks, so a Kubernetes ConfigMap update, which only
// repoints the ..data symlink, still changes the fingerprint. A missing dir
// has a fixed fingerprint of its own.
func Fingerprint(dir string) (string, error) {
	if dir == "" {
		return "none", nil
	}
	files, err := ruleFiles(dir)
	if errors.Is(err, os.ErrNotExist) {
		return "absent", nil
	}
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, f := range files {
		_, _ = io.WriteString(h, f)
		h.Write([]byte{0})
		fh, err := os.Open(f)
		if err != nil {
			// A file vanishing mid-scan is a change in progress; let the
			// debounce settle it rather than failing the watch.
			_, _ = io.WriteString(h, "unreadable:"+err.Error())
			continue
		}
		_, _ = io.Copy(h, io.LimitReader(fh, MaxFileSize+1))
		fh.Close()
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
