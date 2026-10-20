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

// Loop runs fn immediately and then every interval until ctx ends.
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
