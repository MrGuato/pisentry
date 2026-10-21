// Package detect holds the pisentry detectors. Each detector is a small,
// independently testable unit that turns host signals into Top 10 events.
package detect

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/metrics"
	"github.com/MrGuato/pisentry/internal/state"
)

// Deps is what every detector gets.
type Deps struct {
	Cfg   *config.Config
	Emit  event.Emitter
	Store *state.Store
	M     *metrics.Set
	Log   *slog.Logger
	Now   func() time.Time
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d Deps) emit(ev event.Event) {
	if ev.SchemaVersion == 0 {
		ev.SchemaVersion = event.SchemaVersion
	}
	if ev.ID == "" {
		ev.ID = event.NewID()
	}
	d.Emit.Emit(ev)
}

func userEntity(name string) *event.UserEntity {
	u := &event.UserEntity{Name: name}
	if name == "root" {
		u.UID = event.IntPtr(0)
	}
	return u
}

// learning reports whether we are still inside the initial learning period.
func (d Deps) learning() bool {
	var created time.Time
	d.Store.View(func(s *state.State) { created = s.Created })
	return d.now().Sub(created) < d.Cfg.LearningPeriod.Duration
}

// resumeMin is the shortest interval whose schedule survives a restart.
// Faster detectors just run on start; saving their run times would rewrite
// the state file every few seconds.
const resumeMin = 10 * time.Minute

// Loop runs fn every interval until ctx ends. The first run comes right
// away, unless the schedule is at least resumeMin and an earlier process
// finished a run less than one interval ago. Then it waits out the rest,
// so an agent that restarts does not repeat a long scan (the SUID walk)
// on every start.
func Loop(ctx context.Context, d Deps, name string, interval time.Duration, fn func() error) {
	run := func() {
		defer func() {
			if r := recover(); r != nil {
				d.Log.Error("detector panic", "detector", name, "panic", r)
				d.M.DetectorErrors.Inc(name)
			}
		}()
		if err := fn(); err != nil {
			d.Log.Warn("detector error", "detector", name, "err", err)
			d.M.DetectorErrors.Inc(name)
			return
		}
		d.M.DetectorLastRun.Set(float64(time.Now().Unix()), name)
		if interval >= resumeMin {
			d.Store.Update(func(s *state.State) { s.Baselines.LastRun[name] = d.now() })
		}
	}
	if wait, last := d.resumeDelay(name, interval); wait > 0 {
		d.M.DetectorLastRun.Set(float64(last.Unix()), name)
		d.Log.Info("detector resumes its schedule", "detector", name, "next_run_in", wait.Round(time.Second).String())
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
	run()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// resumeDelay is how long a restarted detector should wait before its first
// run, and when the last run finished. Zero means run now: no saved run, a
// fast schedule, an overdue scan, or a saved time in the future (clock moved).
func (d Deps) resumeDelay(name string, interval time.Duration) (time.Duration, time.Time) {
	if interval < resumeMin {
		return 0, time.Time{}
	}
	var last time.Time
	d.Store.View(func(s *state.State) { last = s.Baselines.LastRun[name] })
	if last.IsZero() {
		return 0, last
	}
	since := d.now().Sub(last)
	if since < 0 || since >= interval {
		return 0, last
	}
	return interval - since, last
}

func parsePrefixes(cidrs []string) []netip.Prefix {
	var out []netip.Prefix
	for _, c := range cidrs {
		if !strings.Contains(c, "/") {
			if a, err := netip.ParseAddr(c); err == nil {
				out = append(out, netip.PrefixFrom(a, a.BitLen()))
			}
			continue
		}
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

func inPrefixes(ip string, ps []netip.Prefix) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func maxSev(a, b event.Severity) event.Severity {
	if a > b {
		return a
	}
	return b
}
