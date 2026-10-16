// Package alert pushes high-severity events to ntfy, Discord, Slack or a
// generic JSON webhook. Delivery is async and rate limited so a brute-force
// storm cannot turn into a notification storm.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/metrics"
)

type Webhook struct {
	typ, url, token string
	min             event.Severity
	maxPerHour      int
	ch              chan event.Event
	client          *http.Client
	m               *metrics.Set
	log             *slog.Logger

	windowStart time.Time
	sent        int
	sentCrit    int
}

// New returns nil, nil when alerts are not configured.
func New(c config.AlertConfig, m *metrics.Set, log *slog.Logger) (*Webhook, error) {
	if c.Type == "" {
		return nil, nil
	}
	url := c.URL
	if c.URLEnv != "" && os.Getenv(c.URLEnv) != "" {
		url = os.Getenv(c.URLEnv)
	}
	if url == "" {
		return nil, fmt.Errorf("alerts.type=%s but no URL (set alerts.url or $%s)", c.Type, c.URLEnv)
	}
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return nil, fmt.Errorf("alert URL must be http(s)")
	}
	tok := ""
	if c.TokenEnv != "" {
		tok = os.Getenv(c.TokenEnv)
	}
	return &Webhook{
		typ: c.Type, url: url, token: tok, min: c.MinSeverity, maxPerHour: c.MaxPerHour,
		ch: make(chan event.Event, 128), client: &http.Client{Timeout: 10 * time.Second},
		m: m, log: log,
	}, nil
}

// Handle enqueues without blocking the detector that emitted the event.
func (w *Webhook) Handle(ev event.Event) {
	if ev.Severity < w.min {
		return
	}
	select {
	case w.ch <- ev:
	default:
		w.m.AlertsDropped.Inc("queue_full")
	}
}

func (w *Webhook) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-w.ch:
			now := time.Now()
			if now.Sub(w.windowStart) > time.Hour {
				w.windowStart, w.sent, w.sentCrit = now, 0, 0
			}
			// Criticals get their own budget so a flood of High events (easy
			// for an attacker to generate) cannot starve a reverse-shell alert.
			used, limit := &w.sent, w.maxPerHour
			if ev.Severity == event.Critical {
				used, limit = &w.sentCrit, w.maxPerHour*2
			}
			if limit > 0 && *used >= limit {
				w.m.AlertsDropped.Inc("rate_limit")
				continue
			}
			if err := w.Send(ctx, ev); err != nil {
				time.Sleep(2 * time.Second)
				if err = w.Send(ctx, ev); err != nil {
					w.m.AlertsDropped.Inc("error")
					w.log.Warn("alert delivery failed", "err", err)
					continue
				}
			}
			*used++
			w.m.AlertsSent.Inc(w.typ)
		}
	}
}

// Format renders a human-readable title and body.
func Format(ev event.Event) (title, body string) {
	title = fmt.Sprintf("pisentry %s on %s: %s", strings.ToUpper(ev.Severity.String()), ev.Host, ev.CategoryName)
	var b strings.Builder
	b.WriteString(ev.Summary)
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "category: %s %s\n", ev.Category, ev.CategoryName)
	if len(ev.MITRE) > 0 {
		fmt.Fprintf(&b, "mitre: %s\n", strings.Join(ev.MITRE, ", "))
	}
	keys := make([]string, 0, len(ev.Fields))
	for k := range ev.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\n", k, ev.Fields[k])
	}
	fmt.Fprintf(&b, "time: %s", ev.Time.Format(time.RFC3339))
	return title, b.String()
}

// Send delivers one event synchronously.
func (w *Webhook) Send(ctx context.Context, ev event.Event) error {
	title, body := Format(ev)
	var (
		payload []byte
		ctype   = "application/json"
		err     error
	)
	switch w.typ {
	case "ntfy":
		payload, ctype = []byte(body), "text/plain; charset=utf-8"
	case "discord":
		// Attacker-influenced text must not close the code block or ping anyone.
		safe := strings.ReplaceAll(body, "`", "'")
		msg := "**" + strings.ReplaceAll(title, "`", "'") + "**\n```\n" + safe + "\n```"
		if len(msg) > 1990 {
			msg = msg[:1980] + "\n```"
		}
		payload, err = json.Marshal(map[string]any{
			"username": "pisentry", "content": msg,
			"allowed_mentions": map[string][]string{"parse": {}},
		})
	case "slack":
		esc := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "`", "'")
		payload, err = json.Marshal(map[string]string{"text": "*" + esc.Replace(title) + "*\n```" + esc.Replace(body) + "```"})
	default:
		payload, err = json.Marshal(ev)
	}
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", "pisentry")
	if w.typ == "ntfy" {
		req.Header.Set("Title", title)
		if p := map[event.Severity]string{
			event.Critical: "urgent", event.High: "high", event.Medium: "default",
		}[ev.Severity]; p != "" {
			req.Header.Set("Priority", p)
		}
	}
	if w.token != "" {
		req.Header.Set("Authorization", "Bearer "+w.token)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}
