// Package report builds the ranked "Top 10" view from saved state.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/MrGuato/pisentry/internal/audit"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/state"
)

type Row struct {
	Rank     int            `json:"rank"`
	ID       event.Category `json:"id"`
	Name     string         `json:"name"`
	Events   int            `json:"events"`
	AllTime  int            `json:"all_time"`
	Worst    string         `json:"worst"`
	Score    int            `json:"score"`
	LastSeen *time.Time     `json:"last_seen,omitempty"`
	MITRE    []string       `json:"mitre"`
}

type Report struct {
	Host      string          `json:"host"`
	Generated time.Time       `json:"generated"`
	Window    string          `json:"window"`
	Rows      []Row           `json:"top10"`
	Recent    []event.Event   `json:"recent_high"`
	Failing   []audit.Finding `json:"posture_failing"`
	AuditTime time.Time       `json:"audit_time"`
	StateAge  string          `json:"state_age"`
}

// Build ranks every category by severity-weighted score inside the window,
// then by event count. Categories with nothing to report stay in the table so
// the output always reads as a full status board.
func Build(s state.State, window time.Duration, now time.Time) Report {
	cutoff := now.Add(-window)
	type agg struct {
		n, score int
		worst    event.Severity
		any      bool
		last     time.Time
	}
	by := map[event.Category]*agg{}
	var recent []event.Event
	for _, e := range s.Recent {
		if e.Time.Before(cutoff) {
			continue
		}
		a := by[e.Category]
		if a == nil {
			a = &agg{}
			by[e.Category] = a
		}
		a.n++
		a.score += e.Severity.Weight()
		if !a.any || e.Severity > a.worst {
			a.worst = e.Severity
		}
		a.any = true
		if e.Time.After(a.last) {
			a.last = e.Time
		}
		if e.Severity >= event.High {
			recent = append(recent, e)
		}
	}
	r := Report{Host: s.Host, Generated: now.UTC(), Window: event.Dur(window), AuditTime: s.AuditTime}
	if !s.Saved.IsZero() {
		r.StateAge = now.Sub(s.Saved).Round(time.Second).String()
	}
	for _, ci := range event.Catalog {
		row := Row{ID: ci.ID, Name: ci.Name, MITRE: ci.MITRE, AllTime: s.Totals[ci.ID], Worst: "clean"}
		if a := by[ci.ID]; a != nil {
			row.Events, row.Score, row.Worst = a.n, a.score, a.worst.String()
			t := a.last
			row.LastSeen = &t
		}
		r.Rows = append(r.Rows, row)
	}
	sort.SliceStable(r.Rows, func(i, j int) bool {
		a, b := r.Rows[i], r.Rows[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		return a.ID < b.ID
	})
	for i := range r.Rows {
		r.Rows[i].Rank = i + 1
	}
	sort.Slice(recent, func(i, j int) bool { return recent[i].Time.After(recent[j].Time) })
	if len(recent) > 10 {
		recent = recent[:10]
	}
	r.Recent = recent
	for _, f := range s.Audit {
		if f.Status == audit.Fail {
			r.Failing = append(r.Failing, f)
		}
	}
	return r
}

func ago(t time.Time, now time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

// Text renders the report for a terminal.
func (r Report) Text(w io.Writer) {
	now := r.Generated
	fmt.Fprintf(w, "pisentry Top 10  |  host %s  |  last %s  |  %s\n\n", r.Host, r.Window, now.Format("2006-01-02 15:04 MST"))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tID\tCATEGORY\tEVENTS\tWORST\tLAST SEEN\tALL TIME\tMITRE")
	for _, row := range r.Rows {
		last := "-"
		if row.LastSeen != nil {
			last = ago(*row.LastSeen, now)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%s\t%s\t%d\t%s\n", row.Rank, row.ID, row.Name, row.Events, row.Worst, last, row.AllTime, strings.Join(row.MITRE, ","))
	}
	tw.Flush()

	fmt.Fprintf(w, "\nRecent high and critical (latest %d):\n", len(r.Recent))
	if len(r.Recent) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, e := range r.Recent {
		fmt.Fprintf(w, "  %s  %-8s  %s  %s\n", e.Time.Local().Format("Jan 02 15:04"), e.Severity, e.Category, e.Summary)
	}

	audited := "never"
	if !r.AuditTime.IsZero() {
		audited = ago(r.AuditTime, now)
	}
	fmt.Fprintf(w, "\nPosture (audited %s): %d failing\n", audited, len(r.Failing))
	for _, f := range r.Failing {
		fmt.Fprintf(w, "  %-8s  %-6s  %s", f.Severity, f.ID, f.Title)
		if f.Detail != "" {
			fmt.Fprintf(w, " (%s)", f.Detail)
		}
		fmt.Fprintln(w)
	}
	if r.StateAge != "" {
		fmt.Fprintf(w, "\nstate saved %s ago\n", r.StateAge)
	}
}

// AuditText renders a standalone audit run.
func AuditText(w io.Writer, host string, fs []audit.Finding) {
	fmt.Fprintf(w, "pisentry posture audit  |  host %s\n\n", host)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tSEVERITY\tID\tCHECK\tDETAIL")
	for _, f := range fs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", strings.ToUpper(f.Status), f.Severity, f.ID, f.Title, f.Detail)
	}
	tw.Flush()
	var fails []audit.Finding
	for _, f := range fs {
		if f.Status == audit.Fail && f.Fix != "" {
			fails = append(fails, f)
		}
	}
	if len(fails) > 0 {
		fmt.Fprintln(w, "\nHow to fix:")
		for _, f := range fails {
			fmt.Fprintf(w, "  %s: %s\n", f.ID, f.Fix)
		}
	}
}
