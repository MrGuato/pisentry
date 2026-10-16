package detect

import (
	"context"
	"fmt"

	"github.com/MrGuato/pisentry/internal/audit"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/logsrc"
	"github.com/MrGuato/pisentry/internal/state"
)

// RunLogs feeds every log line to the auth and port-scan detectors.
func RunLogs(ctx context.Context, d Deps, auth *Auth, ps *PortScan) {
	lines, src, err := logsrc.Start(ctx, d.Cfg, d.M, d.Log)
	if err != nil {
		d.Log.Warn("log source unavailable", "err", err)
		d.M.DetectorErrors.Inc("logsrc")
	}
	d.Log.Info("log source", "source", src)
	for l := range lines {
		if auth != nil {
			auth.Handle(l)
		}
		if ps != nil {
			ps.Handle(l)
		}
	}
}

// AuditRunner runs posture checks on a schedule, exports them as gauges and
// emits an event when a check of medium or higher starts failing.
type AuditRunner struct{ d Deps }

func NewAuditRunner(d Deps) *AuditRunner { return &AuditRunner{d: d} }

func (a *AuditRunner) Run(ctx context.Context) {
	Loop(ctx, a.d, "audit", a.d.Cfg.Audit.Interval.Duration, a.Scan)
}

func (a *AuditRunner) Scan() error {
	findings := audit.Run(a.d.Cfg)
	prevFail := map[string]bool{}
	a.d.Store.View(func(s *state.State) {
		for _, f := range s.Audit {
			if f.Status == audit.Fail {
				prevFail[f.ID] = true
			}
		}
	})
	a.d.M.AuditFailing.Reset()
	for _, f := range findings {
		if f.Status == audit.Skip {
			continue
		}
		v := 0.0
		if f.Status == audit.Fail {
			v = 1
		}
		a.d.M.AuditFailing.Set(v, f.ID, string(f.Category), f.Severity.String())
		if f.Status == audit.Fail && !prevFail[f.ID] && f.Severity >= event.Medium {
			a.d.Emit.Emit(event.Event{
				Category: f.Category, Severity: f.Severity, Detector: "audit", Key: "audit|" + f.ID,
				Summary: fmt.Sprintf("Posture check %s failing: %s", f.ID, f.Title),
				Fields:  map[string]string{"check": f.ID, "detail": f.Detail, "fix": f.Fix},
			})
		}
	}
	now := a.d.now().UTC()
	a.d.Store.Update(func(s *state.State) {
		s.Audit, s.AuditTime = findings, now
	})
	return nil
}
