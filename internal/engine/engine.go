// Package engine is the event bus: it enriches, de-duplicates and fans out
// detector events to state, metrics and output sinks.
package engine

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/metrics"
	"github.com/MrGuato/pisentry/internal/state"
)

// Sink receives every event that survives de-duplication.
type Sink interface {
	Handle(event.Event)
}

type Engine struct {
	cfg   *config.Config
	host  string
	store *state.Store
	m     *metrics.Set
	sinks []Sink

	mu        sync.Mutex
	last      map[string]time.Time
	lastPrune time.Time
	Now       func() time.Time
}

func New(cfg *config.Config, host string, store *state.Store, m *metrics.Set) *Engine {
	e := &Engine{cfg: cfg, host: host, store: store, m: m, last: map[string]time.Time{}, Now: time.Now}
	// Pre-create every series at 0 so increase()/rate() see the first event.
	// A counter that appears from nothing loses its first increment in PromQL.
	for _, ci := range event.Catalog {
		for _, s := range event.AllSeverities {
			m.Events.Add(0, string(ci.ID), ci.Name, s.String())
		}
		m.Suppressed.Add(0, string(ci.ID))
	}
	return e
}

func (e *Engine) AddSink(s Sink) { e.sinks = append(e.sinks, s) }

// Emit enriches the event, applies the cooldown and dispatches it.
func (e *Engine) Emit(ev event.Event) {
	now := e.Now().UTC()
	if ev.Time.IsZero() {
		ev.Time = now
	}
	ev.Host = e.host
	// One choke point for attacker-influenced strings (usernames, process
	// names, paths, cmdlines) before they reach JSON, webhooks or a terminal.
	ev.Summary = Truncate(ev.Summary, 400)
	for k, v := range ev.Fields {
		ev.Fields[k] = Truncate(v, 512)
	}
	ci := event.Lookup(ev.Category)
	ev.CategoryName = ci.Name
	if len(ev.MITRE) == 0 {
		ev.MITRE = ci.MITRE
	}
	if ev.Key != "" {
		k := string(ev.Category) + "|" + ev.Key
		e.mu.Lock()
		if t, ok := e.last[k]; ok && now.Sub(t) < e.cfg.Cooldown.Duration {
			e.mu.Unlock()
			e.m.Suppressed.Inc(string(ev.Category))
			return
		}
		e.last[k] = now
		if len(e.last) > 5000 && now.Sub(e.lastPrune) > time.Minute {
			e.lastPrune = now
			for kk, t := range e.last {
				if now.Sub(t) > e.cfg.Cooldown.Duration {
					delete(e.last, kk)
				}
			}
		}
		e.mu.Unlock()
	}
	e.m.Events.Inc(string(ev.Category), ci.Name, ev.Severity.String())
	e.m.LastEvent.Set(float64(now.Unix()), string(ev.Category))
	if e.store != nil {
		e.store.Record(ev)
	}
	for _, s := range e.sinks {
		s.Handle(ev)
	}
}

// JSONSink writes one JSON object per line.
type JSONSink struct {
	mu sync.Mutex
	w  io.Writer
}

func NewJSONSink(w io.Writer) *JSONSink { return &JSONSink{w: w} }

// OpenJSONFile appends to path with 0600 permissions.
func OpenJSONFile(path string) (*JSONSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return NewJSONSink(f), nil
}

func (j *JSONSink) Handle(ev event.Event) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_, _ = j.w.Write(append(b, '\n'))
}

// Truncate neutralizes and shortens untrusted strings: C0/C1 control
// characters (terminal escapes), DEL, bidi overrides and invalid UTF-8 are
// replaced, then the string is cut at n bytes on a rune boundary.
func Truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			return ' '
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f:
			return '?'
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
