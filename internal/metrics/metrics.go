// Package metrics is a tiny Prometheus text-format registry.
//
// pisentry deliberately avoids prometheus/client_golang to stay stdlib-only:
// a security agent should have the smallest possible supply chain.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type Registry struct {
	mu       sync.Mutex
	families []*Vec
}

type Vec struct {
	r      *Registry
	name   string
	help   string
	typ    string
	labels []string
	vals   map[string]*sample
}

type sample struct {
	lv []string
	v  float64
}

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) newVec(typ, name, help string, labels []string) *Vec {
	v := &Vec{r: r, name: name, help: help, typ: typ, labels: labels, vals: map[string]*sample{}}
	r.mu.Lock()
	r.families = append(r.families, v)
	r.mu.Unlock()
	return v
}

func (r *Registry) Counter(name, help string, labels ...string) *Vec {
	return r.newVec("counter", name, help, labels)
}

func (r *Registry) Gauge(name, help string, labels ...string) *Vec {
	return r.newVec("gauge", name, help, labels)
}

func (v *Vec) get(lv []string) *sample {
	if len(lv) != len(v.labels) {
		panic(fmt.Sprintf("metric %s: want %d labels, got %d", v.name, len(v.labels), len(lv)))
	}
	k := strings.Join(lv, "\xff")
	s, ok := v.vals[k]
	if !ok {
		s = &sample{lv: append([]string(nil), lv...)}
		v.vals[k] = s
	}
	return s
}

func (v *Vec) Add(delta float64, lv ...string) {
	v.r.mu.Lock()
	v.get(lv).v += delta
	v.r.mu.Unlock()
}

func (v *Vec) Inc(lv ...string) { v.Add(1, lv...) }

func (v *Vec) Set(val float64, lv ...string) {
	v.r.mu.Lock()
	v.get(lv).v = val
	v.r.mu.Unlock()
}

// Reset drops all series (used for gauges rebuilt from scratch each cycle).
func (v *Vec) Reset() {
	v.r.mu.Lock()
	v.vals = map[string]*sample{}
	v.r.mu.Unlock()
}

// Get returns the current value (tests and the report endpoint use it).
func (v *Vec) Get(lv ...string) float64 {
	v.r.mu.Lock()
	defer v.r.mu.Unlock()
	if s, ok := v.vals[strings.Join(lv, "\xff")]; ok {
		return s.v
	}
	return 0
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)

// Write renders the exposition format, sorted for stable output.
func (r *Registry) Write(w io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.families {
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, f.typ); err != nil {
			return err
		}
		keys := make([]string, 0, len(f.vals))
		for k := range f.vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := f.vals[k]
			var b strings.Builder
			b.WriteString(f.name)
			if len(f.labels) > 0 {
				b.WriteByte('{')
				for i, l := range f.labels {
					if i > 0 {
						b.WriteByte(',')
					}
					b.WriteString(l)
					b.WriteString(`="`)
					b.WriteString(labelEscaper.Replace(s.lv[i]))
					b.WriteByte('"')
				}
				b.WriteByte('}')
			}
			b.WriteByte(' ')
			b.WriteString(formatFloat(s.v))
			b.WriteByte('\n')
			if _, err := io.WriteString(w, b.String()); err != nil {
				return err
			}
		}
	}
	return nil
}

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Set is the fixed set of pisentry metrics, shared by every component.
type Set struct {
	Reg              *Registry
	Up               *Vec
	BuildInfo        *Vec
	Events           *Vec
	LastEvent        *Vec
	Suppressed       *Vec
	AuditFailing     *Vec
	UnexpectedListen *Vec
	SSHFailures      *Vec
	FirewallDrops    *Vec
	DetectorErrors   *Vec
	DetectorLastRun  *Vec
	AlertsSent       *Vec
	AlertsDropped    *Vec
	LogLines         *Vec
	BaselineFiles    *Vec
	RulesLoaded      *Vec
	RulesLastReload  *Vec
	RulesReloadFails *Vec
}

func NewSet() *Set {
	r := NewRegistry()
	return &Set{
		Reg:              r,
		Up:               r.Gauge("pisentry_up", "1 while the agent is running.", "host"),
		BuildInfo:        r.Gauge("pisentry_build_info", "Build metadata.", "version", "goarch"),
		Events:           r.Counter("pisentry_events_total", "Security events by Top 10 category and severity.", "category", "name", "severity"),
		LastEvent:        r.Gauge("pisentry_category_last_event_timestamp_seconds", "Unix time of the last event per category.", "category"),
		Suppressed:       r.Counter("pisentry_events_suppressed_total", "Events dropped by the per-key cooldown.", "category"),
		AuditFailing:     r.Gauge("pisentry_audit_check_failing", "1 if a posture check is failing.", "check", "category", "severity"),
		UnexpectedListen: r.Gauge("pisentry_unexpected_listeners", "Listening sockets not in the baseline right now."),
		SSHFailures:      r.Counter("pisentry_ssh_auth_failures_total", "Failed SSH authentication log lines."),
		FirewallDrops:    r.Counter("pisentry_firewall_drop_lines_total", "Kernel firewall log lines with SRC/DPT seen."),
		DetectorErrors:   r.Counter("pisentry_detector_errors_total", "Detector errors.", "detector"),
		DetectorLastRun:  r.Gauge("pisentry_detector_last_run_timestamp_seconds", "Unix time each detector last completed a cycle.", "detector"),
		AlertsSent:       r.Counter("pisentry_alerts_sent_total", "Webhook alerts delivered.", "type"),
		AlertsDropped:    r.Counter("pisentry_alerts_dropped_total", "Webhook alerts dropped (rate limit or error).", "reason"),
		LogLines:         r.Counter("pisentry_log_lines_total", "Log lines read.", "source"),
		BaselineFiles:    r.Gauge("pisentry_baseline_entries", "Entries in each learned baseline.", "baseline"),
		RulesLoaded:      r.Gauge("pisentry_rules_loaded", "Rules in the active rule set."),
		RulesLastReload:  r.Gauge("pisentry_rules_last_reload_timestamp_seconds", "Unix time the active rule set was loaded."),
		RulesReloadFails: r.Counter("pisentry_rules_reload_failures_total", "Rule reloads rejected; the previous rule set stayed active."),
	}
}
